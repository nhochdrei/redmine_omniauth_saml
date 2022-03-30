require_dependency 'user'

module OmniAuthSamlUser
  extend ActiveSupport::Concern

  included do
    prepend OmniAuthSamlUserPrependMethods
  end

  class_methods do
    def find_or_create_from_omniauth(omniauth)
      user_attributes = Redmine::OmniAuthSAML.user_attributes_from_saml omniauth
      user = self.find_by_login(user_attributes[:login])
      unless user
        user = EmailAddress.find_by(address: user_attributes[:mail]).try(:user)
        if user.nil? && Redmine::OmniAuthSAML.onthefly_creation?
          user = new user_attributes
          user.created_by_omniauth_saml = true
          user.login = user_attributes[:login]
          user.language = Setting.default_language
          user.activate
          user.save!
          user.reload
        end
      end
      Redmine::OmniAuthSAML.on_login_callback.call(omniauth, user) if Redmine::OmniAuthSAML.on_login_callback
      user
    end
  end

  module OmniAuthSamlUserPrependMethods
    def change_password_allowed?
      super && !created_by_omniauth_saml?
    end
  end

end

unless User.included_modules.include?(OmniAuthSamlUser)
  User.send(:include, OmniAuthSamlUser)
end

