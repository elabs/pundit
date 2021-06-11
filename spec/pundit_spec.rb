# frozen_string_literal: true

require "spec_helper"

RSpec.describe Pundit do
  let(:user) { double }
  let(:post) { Post.new(user) }
  let(:customer_post) { Customer::Post.new(user) }
  let(:post_four_five_six) { PostFourFiveSix.new(user) }
  let(:comment) { Comment.new }
  let(:comment_four_five_six) { CommentFourFiveSix.new }
  let(:article) { Article.new }
  let(:controller) { Controller.new(user, "update", {}) }
  let(:artificial_blog) { ArtificialBlog.new }
  let(:article_tag) { ArticleTag.new }
  let(:comments_relation) { CommentsRelation.new }
  let(:empty_comments_relation) { CommentsRelation.new(true) }
  let(:tag_four_five_six) { ProjectOneTwoThree::TagFourFiveSix.new(user) }
  let(:avatar_four_five_six) { ProjectOneTwoThree::AvatarFourFiveSix.new }
  let(:wiki) { Wiki.new }
  let(:thread) { Thread.new }

  describe ".authorize" do
    it "infers the policy and authorizes based on it" do
      expect(Pundit.authorize(user, post, :update?)).to be_truthy
    end

    it "returns the record on successful authorization" do
      expect(Pundit.authorize(user, post, :update?)).to eq(post)
    end

    it "returns the record when passed record with namespace " do
      expect(Pundit.authorize(user, [:project, comment], :update?)).to eq(comment)
    end

    it "returns the record when passed record with nested namespace " do
      expect(Pundit.authorize(user, [:project, :admin, comment], :update?)).to eq(comment)
    end

    it "returns the policy name symbol when passed record with headless policy" do
      expect(Pundit.authorize(user, :publication, :create?)).to eq(:publication)
    end

    it "returns the class when passed record not a particular instance" do
      expect(Pundit.authorize(user, Post, :show?)).to eq(Post)
    end

    it "can be given a different policy class" do
      expect(Pundit.authorize(user, post, :create?, policy_class: PublicationPolicy)).to be_truthy
    end

    it "works with anonymous class policies" do
      expect(Pundit.authorize(user, article_tag, :show?)).to be_truthy
      expect { Pundit.authorize(user, article_tag, :destroy?) }.to raise_error(Pundit::NotAuthorizedError)
    end

    it "raises an error with a query and action" do
      # rubocop:disable Style/MultilineBlockChain
      expect do
        Pundit.authorize(user, post, :destroy?)
      end.to raise_error(Pundit::NotAuthorizedError, "not allowed to destroy? this Post") do |error|
        expect(error.query).to eq :destroy?
        expect(error.record).to eq post
        expect(error.policy).to eq Pundit.policy(user, post)
      end
      # rubocop:enable Style/MultilineBlockChain
    end

    it "raises an error with a invalid policy constructor" do
      expect do
        Pundit.authorize(user, wiki, :update?)
      end.to raise_error(Pundit::InvalidConstructorError, "Invalid #<WikiPolicy> constructor is called")
    end
  end

  describe ".policy_scope" do
    it "returns an instantiated policy scope given a plain model class" do
      expect(Pundit.policy_scope(user, Post)).to eq :published
    end

    it "returns an instantiated policy scope given an active model class" do
      expect(Pundit.policy_scope(user, Comment)).to eq CommentScope.new(Comment)
    end

    it "returns an instantiated policy scope given an active record relation" do
      expect(Pundit.policy_scope(user, comments_relation)).to eq CommentScope.new(comments_relation)
    end

    it "returns an instantiated policy scope given an empty active record relation" do
      expect(Pundit.policy_scope(user, empty_comments_relation)).to eq CommentScope.new(empty_comments_relation)
    end

    it "returns an instantiated policy scope given an array of a symbol and plain model class" do
      expect(Pundit.policy_scope(user, [:project, Post])).to eq :read
    end

    it "returns an instantiated policy scope given an array of a symbol and active model class" do
      expect(Pundit.policy_scope(user, [:project, Comment])).to eq Comment
    end

    it "returns nil if the given policy scope can't be found" do
      expect(Pundit.policy_scope(user, Article)).to be_nil
    end

    it "raises an exception if nil object given" do
      expect { Pundit.policy_scope(user, nil) }.to raise_error(Pundit::NotDefinedError)
    end

    it "raises an error with a invalid policy scope constructor" do
      expect do
        Pundit.policy_scope(user, Wiki)
      end.to raise_error(Pundit::InvalidConstructorError, "Invalid #<WikiPolicy::Scope> constructor is called")
    end

    it "raises an original error with a policy scope that contains error" do
      expect do
        Pundit.policy_scope(user, Thread)
      end.to raise_error(ArgumentError)
    end
  end

  describe ".policy_scope!" do
    it "returns an instantiated policy scope given a plain model class" do
      expect(Pundit.policy_scope!(user, Post)).to eq :published
    end

    it "returns an instantiated policy scope given an active model class" do
      expect(Pundit.policy_scope!(user, Comment)).to eq CommentScope.new(Comment)
    end

    it "throws an exception if the given policy scope can't be found" do
      expect { Pundit.policy_scope!(user, Article) }.to raise_error(Pundit::NotDefinedError)
    end

    it "throws an exception if the given policy scope can't be found" do
      expect { Pundit.policy_scope!(user, ArticleTag) }.to raise_error(Pundit::NotDefinedError)
    end

    it "throws an exception if the given policy scope is nil" do
      expect do
        Pundit.policy_scope!(user, nil)
      end.to raise_error(Pundit::NotDefinedError, "Cannot scope NilClass")
    end

    it "returns an instantiated policy scope given an array of a symbol and plain model class" do
      expect(Pundit.policy_scope!(user, [:project, Post])).to eq :read
    end

    it "returns an instantiated policy scope given an array of a symbol and active model class" do
      expect(Pundit.policy_scope!(user, [:project, Comment])).to eq Comment
    end

    it "raises an error with a invalid policy scope constructor" do
      expect do
        Pundit.policy_scope(user, Wiki)
      end.to raise_error(Pundit::InvalidConstructorError, "Invalid #<WikiPolicy::Scope> constructor is called")
    end
  end

  describe ".policy" do
    it "returns an instantiated policy given a plain model instance" do
      policy = Pundit.policy(user, post)
      expect(policy.user).to eq user
      expect(policy.post).to eq post
    end

    it "returns an instantiated policy given an active model instance" do
      policy = Pundit.policy(user, comment)
      expect(policy.user).to eq user
      expect(policy.comment).to eq comment
    end

    it "returns an instantiated policy given a plain model class" do
      policy = Pundit.policy(user, Post)
      expect(policy.user).to eq user
      expect(policy.post).to eq Post
    end

    it "returns an instantiated policy given an active model class" do
      policy = Pundit.policy(user, Comment)
      expect(policy.user).to eq user
      expect(policy.comment).to eq Comment
    end

    it "returns an instantiated policy given a symbol" do
      policy = Pundit.policy(user, :criteria)
      expect(policy.class).to eq CriteriaPolicy
      expect(policy.user).to eq user
      expect(policy.criteria).to eq :criteria
    end

    it "returns an instantiated policy given an array of symbols" do
      policy = Pundit.policy(user, %i[project criteria])
      expect(policy.class).to eq Project::CriteriaPolicy
      expect(policy.user).to eq user
      expect(policy.criteria).to eq :criteria
    end

    it "returns an instantiated policy given an array of a symbol and plain model instance" do
      policy = Pundit.policy(user, [:project, post])
      expect(policy.class).to eq Project::PostPolicy
      expect(policy.user).to eq user
      expect(policy.post).to eq post
    end

    it "returns an instantiated policy given an array of a symbol and a model instance with policy_class override" do
      policy = Pundit.policy(user, [:project, customer_post])
      expect(policy.class).to eq Project::PostPolicy
      expect(policy.user).to eq user
      expect(policy.post).to eq customer_post
    end

    it "returns an instantiated policy given an array of a symbol and an active model instance" do
      policy = Pundit.policy(user, [:project, comment])
      expect(policy.class).to eq Project::CommentPolicy
      expect(policy.user).to eq user
      expect(policy.comment).to eq comment
    end

    it "returns an instantiated policy given an array of a symbol and a plain model class" do
      policy = Pundit.policy(user, [:project, Post])
      expect(policy.class).to eq Project::PostPolicy
      expect(policy.user).to eq user
      expect(policy.post).to eq Post
    end

    it "raises an error with a invalid policy constructor" do
      expect do
        Pundit.policy(user, Wiki)
      end.to raise_error(Pundit::InvalidConstructorError, "Invalid #<WikiPolicy> constructor is called")
    end

    it "returns an instantiated policy given an array of a symbol and an active model class" do
      policy = Pundit.policy(user, [:project, Comment])
      expect(policy.class).to eq Project::CommentPolicy
      expect(policy.user).to eq user
      expect(policy.comment).to eq Comment
    end

    it "returns an instantiated policy given an array of a symbol and a class with policy_class override" do
      policy = Pundit.policy(user, [:project, Customer::Post])
      expect(policy.class).to eq Project::PostPolicy
      expect(policy.user).to eq user
      expect(policy.post).to eq Customer::Post
    end

    it "returns correct policy class for an array of a multi-word symbols" do
      policy = Pundit.policy(user, %i[project_one_two_three criteria_four_five_six])
      expect(policy.class).to eq ProjectOneTwoThree::CriteriaFourFiveSixPolicy
    end

    it "returns correct policy class for an array of a multi-word symbol and a multi-word plain model instance" do
      policy = Pundit.policy(user, [:project_one_two_three, post_four_five_six])
      expect(policy.class).to eq ProjectOneTwoThree::PostFourFiveSixPolicy
    end

    it "returns correct policy class for an array of a multi-word symbol and a multi-word active model instance" do
      policy = Pundit.policy(user, [:project_one_two_three, comment_four_five_six])
      expect(policy.class).to eq ProjectOneTwoThree::CommentFourFiveSixPolicy
    end

    it "returns correct policy class for an array of a multi-word symbol and a multi-word plain model class" do
      policy = Pundit.policy(user, [:project_one_two_three, PostFourFiveSix])
      expect(policy.class).to eq ProjectOneTwoThree::PostFourFiveSixPolicy
    end

    it "returns correct policy class for an array of a multi-word symbol and a multi-word active model class" do
      policy = Pundit.policy(user, [:project_one_two_three, CommentFourFiveSix])
      expect(policy.class).to eq ProjectOneTwoThree::CommentFourFiveSixPolicy
    end

    it "returns correct policy class for a multi-word scoped plain model class" do
      policy = Pundit.policy(user, ProjectOneTwoThree::TagFourFiveSix)
      expect(policy.class).to eq ProjectOneTwoThree::TagFourFiveSixPolicy
    end

    it "returns correct policy class for a multi-word scoped plain model instance" do
      policy = Pundit.policy(user, tag_four_five_six)
      expect(policy.class).to eq ProjectOneTwoThree::TagFourFiveSixPolicy
    end

    it "returns correct policy class for a multi-word scoped active model class" do
      policy = Pundit.policy(user, ProjectOneTwoThree::AvatarFourFiveSix)
      expect(policy.class).to eq ProjectOneTwoThree::AvatarFourFiveSixPolicy
    end

    it "returns correct policy class for a multi-word scoped active model instance" do
      policy = Pundit.policy(user, avatar_four_five_six)
      expect(policy.class).to eq ProjectOneTwoThree::AvatarFourFiveSixPolicy
    end

    it "returns nil if the given policy can't be found" do
      expect(Pundit.policy(user, article)).to be_nil
      expect(Pundit.policy(user, Article)).to be_nil
    end

    it "returns the specified NilClassPolicy for nil" do
      expect(Pundit.policy(user, nil)).to be_a NilClassPolicy
    end

    describe "with .policy_class set on the model" do
      it "returns an instantiated policy given a plain model instance" do
        policy = Pundit.policy(user, artificial_blog)
        expect(policy.user).to eq user
        expect(policy.blog).to eq artificial_blog
      end

      it "returns an instantiated policy given a plain model class" do
        policy = Pundit.policy(user, ArtificialBlog)
        expect(policy.user).to eq user
        expect(policy.blog).to eq ArtificialBlog
      end

      it "returns an instantiated policy given a plain model instance providing an anonymous class" do
        policy = Pundit.policy(user, article_tag)
        expect(policy.user).to eq user
        expect(policy.tag).to eq article_tag
      end

      it "returns an instantiated policy given a plain model class providing an anonymous class" do
        policy = Pundit.policy(user, ArticleTag)
        expect(policy.user).to eq user
        expect(policy.tag).to eq ArticleTag
      end
    end
  end

  describe ".policy!" do
    it "returns an instantiated policy given a plain model instance" do
      policy = Pundit.policy!(user, post)
      expect(policy.user).to eq user
      expect(policy.post).to eq post
    end

    it "returns an instantiated policy given an active model instance" do
      policy = Pundit.policy!(user, comment)
      expect(policy.user).to eq user
      expect(policy.comment).to eq comment
    end

    it "returns an instantiated policy given a plain model class" do
      policy = Pundit.policy!(user, Post)
      expect(policy.user).to eq user
      expect(policy.post).to eq Post
    end

    it "returns an instantiated policy given an active model class" do
      policy = Pundit.policy!(user, Comment)
      expect(policy.user).to eq user
      expect(policy.comment).to eq Comment
    end

    it "returns an instantiated policy given a symbol" do
      policy = Pundit.policy!(user, :criteria)
      expect(policy.class).to eq CriteriaPolicy
      expect(policy.user).to eq user
      expect(policy.criteria).to eq :criteria
    end

    it "returns an instantiated policy given an array of symbols" do
      policy = Pundit.policy!(user, %i[project criteria])
      expect(policy.class).to eq Project::CriteriaPolicy
      expect(policy.user).to eq user
      expect(policy.criteria).to eq :criteria
    end

    it "throws an exception if the given policy can't be found" do
      expect { Pundit.policy!(user, article) }.to raise_error(Pundit::NotDefinedError)
      expect { Pundit.policy!(user, Article) }.to raise_error(Pundit::NotDefinedError)
    end

    it "returns the specified NilClassPolicy for nil" do
      expect(Pundit.policy!(user, nil)).to be_a NilClassPolicy
    end

    it "raises an error with a invalid policy constructor" do
      expect do
        Pundit.policy(user, Wiki)
      end.to raise_error(Pundit::InvalidConstructorError, "Invalid #<WikiPolicy> constructor is called")
    end
  end

  describe "#verify_authorized" do
    it "does nothing when authorized" do
      controller.authorize(post)
      controller.verify_authorized
    end

    it "raises an exception when not authorized" do
      expect { controller.verify_authorized }.to raise_error(Pundit::AuthorizationNotPerformedError)
    end
  end

  describe "#verify_policy_scoped" do
    it "does nothing when policy_scope is used" do
      controller.policy_scope(Post)
      controller.verify_policy_scoped
    end

    it "raises an exception when policy_scope is not used" do
      expect { controller.verify_policy_scoped }.to raise_error(Pundit::PolicyScopingNotPerformedError)
    end
  end

  describe "#pundit_policy_authorized?" do
    it "is true when authorized" do
      controller.authorize(post)
      expect(controller.pundit_policy_authorized?).to be true
    end

    it "is false when not authorized" do
      expect(controller.pundit_policy_authorized?).to be false
    end
  end

  describe "#pundit_policy_scoped?" do
    it "is true when policy_scope is used" do
      controller.policy_scope(Post)
      expect(controller.pundit_policy_scoped?).to be true
    end

    it "is false when policy scope is not used" do
      expect(controller.pundit_policy_scoped?).to be false
    end
  end

  describe "#authorize" do
    it "infers the policy name and authorizes based on it" do
      expect(controller.authorize(post)).to be_truthy
    end

    it "returns the record on successful authorization" do
      expect(controller.authorize(post)).to eq(post)
    end

    it "returns the record when passed record with namespace " do
      expect(controller.authorize([:project, comment], :update?)).to eq(comment)
    end

    it "returns the record when passed record with nested namespace " do
      expect(controller.authorize([:project, :admin, comment], :update?)).to eq(comment)
    end

    it "returns the policy name symbol when passed record with headless policy" do
      expect(controller.authorize(:publication, :create?)).to eq(:publication)
    end

    it "returns the class when passed record not a particular instance" do
      expect(controller.authorize(Post, :show?)).to eq(Post)
    end

    it "can be given a different permission to check" do
      expect(controller.authorize(post, :show?)).to be_truthy
      expect { controller.authorize(post, :destroy?) }.to raise_error(Pundit::NotAuthorizedError)
    end

    it "can be given a different policy class" do
      expect(controller.authorize(post, :create?, policy_class: PublicationPolicy)).to be_truthy
    end

    it "works with anonymous class policies" do
      expect(controller.authorize(article_tag, :show?)).to be_truthy
      expect { controller.authorize(article_tag, :destroy?) }.to raise_error(Pundit::NotAuthorizedError)
    end

    it "throws an exception when the permission check fails" do
      expect { controller.authorize(Post.new) }.to raise_error(Pundit::NotAuthorizedError)
    end

    it "throws an exception when a policy cannot be found" do
      expect { controller.authorize(Article) }.to raise_error(Pundit::NotDefinedError)
    end

    it "caches the policy" do
      expect(controller.policies[post]).to be_nil
      controller.authorize(post)
      expect(controller.policies[post]).not_to be_nil
    end

    it "raises an error when the given record is nil" do
      expect { controller.authorize(nil, :destroy?) }.to raise_error(Pundit::NotAuthorizedError)
    end

    it "raises an error with a invalid policy constructor" do
      expect { controller.authorize(wiki, :destroy?) }.to raise_error(Pundit::InvalidConstructorError)
    end
  end

  describe "#skip_authorization" do
    it "disables authorization verification" do
      controller.skip_authorization
      expect { controller.verify_authorized }.not_to raise_error
    end
  end

  describe "#skip_policy_scope" do
    it "disables policy scope verification" do
      controller.skip_policy_scope
      expect { controller.verify_policy_scoped }.not_to raise_error
    end
  end

  describe "#pundit_user" do
    it "returns the same thing as current_user" do
      expect(controller.pundit_user).to eq controller.current_user
    end
  end

  describe "#policy" do
    it "returns an instantiated policy" do
      policy = controller.policy(post)
      expect(policy.user).to eq user
      expect(policy.post).to eq post
    end

    it "throws an exception if the given policy can't be found" do
      expect { controller.policy(article) }.to raise_error(Pundit::NotDefinedError)
    end

    it "raises an error with a invalid policy constructor" do
      expect { controller.policy(wiki) }.to raise_error(Pundit::InvalidConstructorError)
    end

    it "allows policy to be injected" do
      new_policy = OpenStruct.new
      controller.policies[post] = new_policy

      expect(controller.policy(post)).to eq new_policy
    end
  end

  describe "#policy_scope" do
    it "returns an instantiated policy scope" do
      expect(controller.policy_scope(Post)).to eq :published
    end

    it "allows policy scope class to be overriden" do
      expect(controller.policy_scope(Post, policy_scope_class: PublicationPolicy::Scope)).to eq :published
    end

    it "allows override policy scope class with extra attributes" do
      expect(controller.policy_scope(Post, policy_scope_class: PublicationPolicy::Scope, action: "archived")).to(
        eq(:archived)
      )
    end

    it "throws an exception if the given policy can't be found" do
      expect { controller.policy_scope(Article) }.to raise_error(Pundit::NotDefinedError)
    end

    it "raises an error with a invalid policy scope constructor" do
      expect { controller.policy_scope(Wiki) }.to raise_error(Pundit::InvalidConstructorError)
    end

    it "allows policy_scope to be injected" do
      new_scope = OpenStruct.new
      controller.policy_scopes[Post] = new_scope

      expect(controller.policy_scope(Post)).to eq new_scope
    end
  end

  describe "#permitted_attributes" do
    it "checks policy for permitted attributes" do
      params = ActionController::Parameters.new(
        post: {
          title: "Hello",
          votes: 5,
          admin: true
        }
      )

      action = "update"

      expect(Controller.new(user, action, params).permitted_attributes(post).to_h).to eq(
        "title" => "Hello",
        "votes" => 5
      )
      expect(Controller.new(double, action, params).permitted_attributes(post).to_h).to eq("votes" => 5)
    end

    it "checks policy for permitted attributes for record of a ActiveModel type" do
      params = ActionController::Parameters.new(
        customer_post: {
          title: "Hello",
          votes: 5,
          admin: true
        }
      )

      action = "update"

      expect(Controller.new(user, action, params).permitted_attributes(customer_post).to_h).to eq(
        "title" => "Hello",
        "votes" => 5
      )
      expect(Controller.new(double, action, params).permitted_attributes(customer_post).to_h).to eq(
        "votes" => 5
      )
    end
  end

  describe "#permitted_attributes_for_action" do
    it "is checked if it is defined in the policy" do
      params = ActionController::Parameters.new(
        post: {
          title: "Hello",
          body: "blah",
          votes: 5,
          admin: true
        }
      )

      action = "revise"
      expect(Controller.new(user, action, params).permitted_attributes(post).to_h).to eq("body" => "blah")
    end

    it "can be explicitly set" do
      params = ActionController::Parameters.new(
        post: {
          title: "Hello",
          body: "blah",
          votes: 5,
          admin: true
        }
      )

      action = "update"
      expect(Controller.new(user, action, params).permitted_attributes(post, :revise).to_h).to eq("body" => "blah")
    end
  end

  describe "Pundit::NotAuthorizedError" do
    it "can be initialized with a string as message" do
      error = Pundit::NotAuthorizedError.new("must be logged in")
      expect(error.message).to eq "must be logged in"
    end
  end
end
