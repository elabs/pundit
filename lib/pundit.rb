# frozen_string_literal: true

require "pundit/version"
require "pundit/policy_finder"
require "active_support/concern"
require "active_support/core_ext/string/inflections"
require "active_support/core_ext/object/blank"
require "active_support/core_ext/module/introspection"
require "active_support/dependencies/autoload"

# @api private
# To avoid name clashes with common Error naming when mixing in Pundit,
# keep it here with compact class style definition.
class Pundit::Error < StandardError; end # rubocop:disable Style/ClassAndModuleChildren

# @api public
module Pundit
  SUFFIX = "Policy"

  # @api private
  module Generators; end

  # @api private
  module ExtraScopeAttributes
    attr_accessor :extra

    def initialize(*params, **extra)
      super(*params)
      self.extra = extra
    end
  end

  # Error that will be raised when authorization has failed
  class NotAuthorizedError < Error
    attr_reader :query, :record, :policy, :reason

    def initialize(options = {})
      if options.is_a? String
        message = options
      else
        @query  = options[:query]
        @record = options[:record]
        @policy = options[:policy]
        @reason = options[:reason]

        message = options.fetch(:message) { "not allowed to #{query} this #{record.class}" }
      end

      super(message)
    end
  end

  # Error that will be raised if a policy or policy scope constructor is not called correctly.
  class InvalidConstructorError < Error; end

  # Error that will be raised if a controller action has not called the
  # `authorize` or `skip_authorization` methods.
  class AuthorizationNotPerformedError < Error; end

  # Error that will be raised if a controller action has not called the
  # `policy_scope` or `skip_policy_scope` methods.
  class PolicyScopingNotPerformedError < AuthorizationNotPerformedError; end

  # Error that will be raised if a policy or policy scope is not defined.
  class NotDefinedError < Error; end

  extend ActiveSupport::Concern

  class << self
    # Retrieves the policy for the given record, initializing it with the
    # record and user and finally throwing an error if the user is not
    # authorized to perform the given action.
    #
    # @param user [Object] the user that initiated the action
    # @param record [Object] the object we're checking permissions of
    # @param query [Symbol, String] the predicate method to check on the policy (e.g. `:show?`)
    # @param policy_class [Class] the policy class we want to force use of
    # @raise [NotAuthorizedError] if the given query method returned false
    # @return [Object] Always returns the passed object record
    def authorize(user, record, query, policy_class: nil)
      policy = policy_class ? policy_class.new(user, record) : policy!(user, record)

      raise NotAuthorizedError, query: query, record: record, policy: policy unless policy.public_send(query)

      record.is_a?(Array) ? record.last : record
    end

    # Retrieves the policy scope for the given record.
    #
    # @see https://github.com/varvet/pundit#scopes
    # @param user [Object] the user that initiated the action
    # @param scope [Object] the object we're retrieving the policy scope for
    # @raise [InvalidConstructorError] if the policy constructor called incorrectly
    # @return [Scope{#resolve}, nil] instance of scope class which can resolve to a scope
    def policy_scope(user, scope, **extra)
      policy_scope_class = PolicyFinder.new(scope).scope
      return unless policy_scope_class

      unless policy_scope_class.ancestors.include?(ExtraScopeAttributes)
        policy_scope_class.prepend(ExtraScopeAttributes)
      end

      begin
        policy_scope = policy_scope_class.new(user, pundit_model(scope), **extra)
      rescue ArgumentError
        raise InvalidConstructorError, "Invalid #<#{policy_scope_class}> constructor is called"
      end

      policy_scope.resolve
    end

    # Retrieves the policy scope for the given record.
    #
    # @see https://github.com/varvet/pundit#scopes
    # @param user [Object] the user that initiated the action
    # @param scope [Object] the object we're retrieving the policy scope for
    # @raise [NotDefinedError] if the policy scope cannot be found
    # @raise [InvalidConstructorError] if the policy constructor called incorrectly
    # @return [Scope{#resolve}] instance of scope class which can resolve to a scope
    def policy_scope!(user, scope, **extra)
      policy_scope_class = PolicyFinder.new(scope).scope!
      return unless policy_scope_class

      unless policy_scope_class.ancestors.include?(ExtraScopeAttributes)
        policy_scope_class.prepend(ExtraScopeAttributes)
      end

      begin
        policy_scope = policy_scope_class.new(user, pundit_model(scope), **extra)
      rescue ArgumentError
        raise InvalidConstructorError, "Invalid #<#{policy_scope_class}> constructor is called"
      end

      policy_scope.resolve
    end

    # Retrieves the policy for the given record.
    #
    # @see https://github.com/varvet/pundit#policies
    # @param user [Object] the user that initiated the action
    # @param record [Object] the object we're retrieving the policy for
    # @raise [InvalidConstructorError] if the policy constructor called incorrectly
    # @return [Object, nil] instance of policy class with query methods
    def policy(user, record)
      policy = PolicyFinder.new(record).policy
      policy&.new(user, pundit_model(record))
    rescue ArgumentError
      raise InvalidConstructorError, "Invalid #<#{policy}> constructor is called"
    end

    # Retrieves the policy for the given record.
    #
    # @see https://github.com/varvet/pundit#policies
    # @param user [Object] the user that initiated the action
    # @param record [Object] the object we're retrieving the policy for
    # @raise [NotDefinedError] if the policy cannot be found
    # @raise [InvalidConstructorError] if the policy constructor called incorrectly
    # @return [Object] instance of policy class with query methods
    def policy!(user, record)
      policy = PolicyFinder.new(record).policy!
      policy.new(user, pundit_model(record))
    rescue ArgumentError
      raise InvalidConstructorError, "Invalid #<#{policy}> constructor is called"
    end

    private

    def pundit_model(record)
      record.is_a?(Array) ? record.last : record
    end
  end

  # @api private
  module Helper
    def policy_scope(scope)
      pundit_policy_scope(scope)
    end
  end

  included do
    helper Helper if respond_to?(:helper)
    if respond_to?(:helper_method)
      helper_method :policy
      helper_method :pundit_policy_scope
      helper_method :pundit_user
    end
  end

  protected

  # @return [Boolean] whether authorization has been performed, i.e. whether
  #                   one {#authorize} or {#skip_authorization} has been called
  def pundit_policy_authorized?
    !!@_pundit_policy_authorized
  end

  # @return [Boolean] whether policy scoping has been performed, i.e. whether
  #                   one {#policy_scope} or {#skip_policy_scope} has been called
  def pundit_policy_scoped?
    !!@_pundit_policy_scoped
  end

  # Raises an error if authorization has not been performed, usually used as an
  # `after_action` filter to prevent programmer error in forgetting to call
  # {#authorize} or {#skip_authorization}.
  #
  # @see https://github.com/varvet/pundit#ensuring-policies-and-scopes-are-used
  # @raise [AuthorizationNotPerformedError] if authorization has not been performed
  # @return [void]
  def verify_authorized
    raise AuthorizationNotPerformedError, self.class unless pundit_policy_authorized?
  end

  # Raises an error if policy scoping has not been performed, usually used as an
  # `after_action` filter to prevent programmer error in forgetting to call
  # {#policy_scope} or {#skip_policy_scope} in index actions.
  #
  # @see https://github.com/varvet/pundit#ensuring-policies-and-scopes-are-used
  # @raise [AuthorizationNotPerformedError] if policy scoping has not been performed
  # @return [void]
  def verify_policy_scoped
    raise PolicyScopingNotPerformedError, self.class unless pundit_policy_scoped?
  end

  # Retrieves the policy for the given record, initializing it with the record
  # and current user and finally throwing an error if the user is not
  # authorized to perform the given action.
  #
  # @param record [Object] the object we're checking permissions of
  # @param query [Symbol, String] the predicate method to check on the policy (e.g. `:show?`).
  #   If omitted then this defaults to the Rails controller action name.
  # @param policy_class [Class] the policy class we want to force use of
  # @raise [NotAuthorizedError] if the given query method returned false
  # @return [Object] Always returns the passed object record
  def authorize(record, query = nil, policy_class: nil)
    query ||= "#{action_name}?"

    @_pundit_policy_authorized = true

    policy = policy_class ? policy_class.new(pundit_user, record) : policy(record)

    raise NotAuthorizedError, query: query, record: record, policy: policy unless policy.public_send(query)

    record.is_a?(Array) ? record.last : record
  end

  # Allow this action not to perform authorization.
  #
  # @see https://github.com/varvet/pundit#ensuring-policies-and-scopes-are-used
  # @return [void]
  def skip_authorization
    @_pundit_policy_authorized = true
  end

  # Allow this action not to perform policy scoping.
  #
  # @see https://github.com/varvet/pundit#ensuring-policies-and-scopes-are-used
  # @return [void]
  def skip_policy_scope
    @_pundit_policy_scoped = true
  end

  # Retrieves the policy scope for the given record.
  #
  # @see https://github.com/varvet/pundit#scopes
  # @param scope [Object] the object we're retrieving the policy scope for
  # @param policy_scope_class [Class] the policy scope class we want to force use of
  # @return [Scope{#resolve}, nil] instance of scope class which can resolve to a scope
  def policy_scope(scope, policy_scope_class: nil, **extra)
    @_pundit_policy_scoped = true
    return pundit_policy_scope(scope) unless policy_scope_class

    policy_scope_class.prepend(ExtraScopeAttributes) unless policy_scope_class.ancestors.include?(ExtraScopeAttributes)

    policy_scope_class.new(pundit_user, scope, **extra).resolve
  end

  # Retrieves the policy for the given record.
  #
  # @see https://github.com/varvet/pundit#policies
  # @param record [Object] the object we're retrieving the policy for
  # @return [Object, nil] instance of policy class with query methods
  def policy(record)
    policies[record] ||= Pundit.policy!(pundit_user, record)
  end

  # Retrieves a set of permitted attributes from the policy by instantiating
  # the policy class for the given record and calling `permitted_attributes` on
  # it, or `permitted_attributes_for_{action}` if `action` is defined. It then infers
  # what key the record should have in the params hash and retrieves the
  # permitted attributes from the params hash under that key.
  #
  # @see https://github.com/varvet/pundit#strong-parameters
  # @param record [Object] the object we're retrieving permitted attributes for
  # @param action [Symbol, String] the name of the action being performed on the record (e.g. `:update`).
  #   If omitted then this defaults to the Rails controller action name.
  # @return [Hash{String => Object}] the permitted attributes
  def permitted_attributes(record, action = action_name)
    policy = policy(record)
    method_name = if policy.respond_to?("permitted_attributes_for_#{action}")
      "permitted_attributes_for_#{action}"
    else
      "permitted_attributes"
    end
    pundit_params_for(record).permit(*policy.public_send(method_name))
  end

  # Retrieves the params for the given record.
  #
  # @param record [Object] the object we're retrieving params for
  # @return [ActionController::Parameters] the params
  def pundit_params_for(record)
    params.require(PolicyFinder.new(record).param_key)
  end

  # Extra params passed to policy scope.
  #
  # @return [Hash] the extra params
  def policy_scope_extra
    {}
  end

  # Cache of policies. You should not rely on this method.
  #
  # @api private
  # rubocop:disable Naming/MemoizedInstanceVariableName
  def policies
    @_pundit_policies ||= {}
  end
  # rubocop:enable Naming/MemoizedInstanceVariableName

  # Cache of policy scope. You should not rely on this method.
  #
  # @api private
  # rubocop:disable Naming/MemoizedInstanceVariableName
  def policy_scopes
    @_pundit_policy_scopes ||= {}
  end
  # rubocop:enable Naming/MemoizedInstanceVariableName

  # Hook method which allows customizing which user is passed to policies and
  # scopes initialized by {#authorize}, {#policy} and {#policy_scope}.
  #
  # @see https://github.com/varvet/pundit#customize-pundit-user
  # @return [Object] the user object to be used with pundit
  def pundit_user
    current_user
  end

  private

  def pundit_policy_scope(scope)
    policy_scopes[scope] ||= Pundit.policy_scope!(pundit_user, scope, **policy_scope_extra)
  end
end
