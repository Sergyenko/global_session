require File.expand_path(File.join(File.dirname(__FILE__), "..", "global_session"))

# Make sure the namespace exists, to satisfy Rails auto-loading
module GlobalSession
  module Rack
    # Global session middleware.  Note: this class relies on
    # Rack::Cookies being used higher up in the chain.
    class Middleware
      # Make a new global session.
      #
      # The optional block here controls an alternate ticket retrieval
      # method.  If no ticket is stored in the cookie jar, this
      # function is called.  If it returns a non-nil value, that value
      # is the ticket.
      #
      # === Parameters
      # app(Rack client): application to run
      # configuration(String or Configuration): global_session configuration.
      #                                         If a string, is interpreted as a
      #                                         filename to load the config from.
      # directory(String or Directory):         Directory object that provides
      #                                         trust services to the global
      #                                         session implementation. If a
      #                                         string, is interpreted as a
      #                                         filesystem directory containing
      #                                         the public and private keys of
      #                                         authorities, from which default
      #                                         trust services will be initialized.
      #
      # block: optional alternate ticket retrieval function
      def initialize(app, configuration, directory, &block)
        @app = app

        if configuration.instance_of?(String)
          @configuration = Configuration.new(configuration, ENV['RACK_ENV'] || 'development')
        else
          @configuration = configuration
        end

        begin
          klass_name = @configuration['directory'] || 'GlobalSession::Directory'

          #Constantize the type name that was given as a string
          parts = klass_name.split('::')
          namespace = Object
          namespace = namespace.const_get(parts.shift.to_sym) until parts.empty?
          directory_klass = namespace
        rescue Exception => e
          raise ConfigurationError, "Invalid/unknown directory class name #{@configuration['directory']}"
        end

        if directory.instance_of?(String)
          @directory = directory_klass.new(@configuration, directory)
        else
          @directory = directory
        end

        @cookie_retrieval = block
        @cookie_name = @configuration['cookie']['name']
      end

      # Rack request chain. Sets up the global session ticket from
      # the environment and passes it up the chain.
      def call(env)
        env['rack.cookies'] = {} unless env['rack.cookies']

        begin
          read_cookie(env)
        rescue Exception => e
          env['global_session'] = Session.new(@directory)
          handle_error('reading session cookie', env, e)
        end

        tuple = nil

        begin
          tuple = @app.call(env)
        rescue Exception => e
          handle_error('processing request', env, e)
          return tuple
        else
          renew_cookie(env)
          update_cookie(env)
          return tuple
        end
      end

      protected
      
      # Read a cookie from the Rack environment.
      #
      # === Parameters
      # env(Hash): Rack environment.
      def read_cookie(env)
        if env['rack.cookies'].has_key?(@cookie_name)
          env['global_session'] = Session.new(@directory,
                                              env['rack.cookies'][@cookie_name])
          debug_trace(:read_cookie, env, 'got cookie with request')
        elsif @cookie_retrieval && cookie = @cookie_retrieval.call(env)
          env['global_session'] = Session.new(@directory, cookie)
        else
          debug_trace(:read_cookie, env, 'made new cookie')
          env['global_session'] = Session.new(@directory)
        end

        true
      rescue Exception => e
        debug_trace(:read_cookie, env, e)
        raise e
      end

      # Renew the session ticket.
      #
      # === Parameters
      # env(Hash): Rack environment
      def renew_cookie(env)
        return unless env['global_session'].directory.local_authority_name
        return if env['global_session.req.renew'] == false

        if (renew = @configuration['renew']) && env['global_session'] &&
            env['global_session'].expired_at < Time.at(Time.now.utc + 60 * renew.to_i)
          env['global_session'].renew!
          debug_trace(:renew_cookie, env, 'did renew')
        end
      rescue Exception => e
        debug_trace(:renew_cookie, env, e)
        raise e
      end

      # Update the cookie jar with the revised ticket.
      #
      # === Parameters
      # env(Hash): Rack environment
      def update_cookie(env)
        return unless env['global_session'].directory.local_authority_name
        return if env['global_session.req.update'] == false

        begin
          domain = @configuration['cookie']['domain'] || env['SERVER_NAME']
          if env['global_session'] && env['global_session'].valid?
            value = env['global_session'].to_s
            expires = @configuration['ephemeral'] ? nil : env['global_session'].expired_at
            unless env['rack.cookies'].has_key?(@cookie_name) && env['rack.cookies'][@cookie_name] == value
              env['rack.cookies'][@cookie_name] =
                  {:value => value, :domain => domain, :expires => expires, :httponly=>true}
              debug_trace(:update_cookie, env, "did update valid session")
            end
          else
            debug_trace(:update_cookie, env, "did update empty cookie")
            # write an empty cookie
            env['rack.cookies'][@cookie_name] = {:value => nil, :domain => domain, :expires => Time.at(0)}
          end
        rescue Exception => e
          debug_trace(:update_cookie, env, e)
          wipe_cookie(env)
          raise e
        end
      end

      # Delete the global session cookie from the cookie jar.
      #
      # === Parameters
      # env(Hash): Rack environment
      def wipe_cookie(env)
        return unless env['global_session'].directory.local_authority_name
        return if env['global_session.req.update'] == false

        domain = @configuration['cookie']['domain'] || env['SERVER_NAME']
        env['rack.cookies'][@cookie_name] = {:value => nil, :domain => domain, :expires => Time.at(0)}
        debug_trace(:wipe_cookie, env, 'did wipe')
      rescue Exception => e
        debug_trace(:wipe_cookie, env, e)
        raise e
      end

      # Handle exceptions that occur during app invocation. This will either save the error
      # in the Rack environment or raise it, depending on the type of error. The error may
      # also be logged.
      #
      # === Parameters
      # activity(String): name of activity in which error happened
      # env(Hash): Rack environment
      # e(Exception): error that happened
      def handle_error(activity, env, e)
        debug_trace(:handle_error, env, e)

        if env['rack.logger']
          msg = "#{e.class} while #{activity}: #{e}"
          msg += " #{e.backtrace}" unless e.is_a?(ExpiredSession)
          env['rack.logger'].error(msg)
        end

        if e.is_a?(ClientError) || e.is_a?(SecurityError)
          env['global_session.error'] = e
          wipe_cookie(env)
        elsif e.is_a? ConfigurationError
          env['global_session.error'] = e
        else
          raise e
        end
      end

      require 'digest/md5'

      def debug_trace(meth, env, bonus=nil)
        return unless ENV['RAILS_ENV'] == 'staging'
        
        if env['rack.cookies'] && env['rack.cookies'].has_key?('_session_id') 
          local  = env['rack.cookies']['_session_id'][0...8]
        else
          local = 'unknown'.ljust(8)
        end
        
        tm = Time.now.utc.strftime('%H:%M:%S') 

        raw_global = env['rack.cookies'] && env['rack.cookies'][@cookie_name]
        if raw_global
          raw_global = Digest::MD5.hexdigest(raw_global)[0...8]
        else
          raw_global = 'unknown'.ljust(8)
        end

        global = env['global_session']

        File.open('/tmp/global_session.log', 'a') do |f|
          f.print(tm, ' ', meth.to_s.ljust(16), ' l=', local, ' h(g)=', raw_global)

          if global
            f.print ' e=', global.expired_at.to_i
            f.print ' g=', global.id
          end

          if bonus.is_a?(Exception)
            f.print(' ', bonus.class.name, ': ', bonus.message, ' ', bonus.backtrace.first)
          elsif bonus != nil
            f.print ' ', bonus
          end

          if global
            f.print ' {'
            global.each_pair do |key, value|
              f.print key, ':', value, ', '
            end
            f.print '}'
          end

          f.puts
        end
      rescue Exception => e
        begin
          File.open('/tmp/global_session.log', 'a') { |f| f.puts "OH NOES #{e.class.name} - #{e.message}" ; f.puts e.backtrace.join("\n") }
        rescue Exception => e
          #no-op
        end
      end

    end
  end
end

module Rack
  GlobalSession = ::GlobalSession::Rack::Middleware unless defined?(::Rack::GlobalSession)
end
