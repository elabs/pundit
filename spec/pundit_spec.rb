require "pundit"
require "pry"
require "active_support/core_ext"
require "active_model/naming"

class PostPolicy < Struct.new(:user, :post)
  def update?
    post.user == user
  end
  def destroy?
    false
  end
  def show?
    true
  end
  def compare(a, b)
    a == b
  end
end
class PostPolicy::Scope < Struct.new(:user, :scope)
  def resolve
    scope.published
  end
  def custom
    scope.unpublished
  end
  def do_math(a, b)
    a + b
  end
end
class Post < Struct.new(:user)
  def self.published
    :published
  end
  def self.unpublished
    :unpublished
  end
end

class CommentPolicy < Struct.new(:user, :comment); end
class CommentPolicy::Scope < Struct.new(:user, :scope)
  def resolve
    scope
  end
  def custom
    scope.name.pluralize
  end
end
class Comment; extend ActiveModel::Naming; end

class Article; end

class BlogPolicy < Struct.new(:user, :blog); end
class Blog; end
class ArtificialBlog < Blog
  def self.policy_class
    BlogPolicy
  end
end
class ArticleTag
  def self.policy_class
    Struct.new(:user, :tag) do
      def show?
        true
      end
      def destroy?
        false
      end
    end
  end
end

describe Pundit do
  let(:user) { stub }
  let(:post) { Post.new(user) }
  let(:comment) { Comment.new }
  let(:article) { Article.new }
  let(:controller) { stub(:current_user => user, :params => { :action => "update" }).tap { |c| c.extend(Pundit) } }
  let(:artificial_blog) { ArtificialBlog.new }
  let(:article_tag) { ArticleTag.new }

  describe ".policy_scope" do
    it "returns an instantiated policy scope given a plain model class" do
      Pundit.policy_scope(user, Post).should == :published
    end

    it "returns an instantiated custom policy scope given a plain model class" do
      Pundit.policy_scope(user, Post, :custom).should == :unpublished
    end

    it "returns an instantiated custom policy scope with parameters given a plain model class" do
      Pundit.policy_scope(user, Post, :do_math, 2, 3).should == 5
    end

    it "returns an instantiated policy scope given an active model class" do
      Pundit.policy_scope(user, Comment).should == Comment
    end

    it "returns an instantiated custom policy scope given an active model class" do
      Pundit.policy_scope(user, Comment, :custom).should == 'Comments'
    end

    it "returns nil if the given policy scope can't be found" do
      Pundit.policy_scope(user, Article).should be_nil
    end

    it "throws an exception if the given custom scope can't be found" do
      expect{ Pundit.policy_scope(user, Comment, :wrong_name) }.to raise_error(NoMethodError)
    end
  end

  describe ".policy_scope!" do
    it "returns an instantiated policy scope given a plain model class" do
      Pundit.policy_scope!(user, Post).should == :published
    end

    it "returns an instantiated custom policy scope given a plain model class" do
      Pundit.policy_scope!(user, Post, :custom).should == :unpublished
    end

    it "returns an instantiated custom policy scope with parameters given a plain model class" do
      Pundit.policy_scope!(user, Post, :do_math, 2, 3).should == 5
    end

    it "returns an instantiated policy scope given an active model class" do
      Pundit.policy_scope!(user, Comment).should == Comment
    end

    it "returns an instantiated custom policy scope given an active model class" do
      Pundit.policy_scope!(user, Comment, :custom).should == 'Comments'
    end

    it "throws an exception if the given policy scope can't be found" do
      expect { Pundit.policy_scope!(user, Article) }.to raise_error(Pundit::NotDefinedError)
    end

    it "throws an exception if the given policy scope can't be found" do
      expect { Pundit.policy_scope!(user, ArticleTag) }.to raise_error(Pundit::NotDefinedError)
    end

    it "throws an exception if the given custom scope can't be found" do
      expect{ Pundit.policy_scope!(user, Comment, :wrong_name) }.to raise_error(NoMethodError)
    end
  end

  describe ".policy" do
    it "returns an instantiated policy given a plain model instance" do
      policy = Pundit.policy(user, post)
      policy.user.should == user
      policy.post.should == post
    end

    it "returns an instantiated policy given an active model instance" do
      policy = Pundit.policy(user, comment)
      policy.user.should == user
      policy.comment.should == comment
    end

    it "returns an instantiated policy given a plain model class" do
      policy = Pundit.policy(user, Post)
      policy.user.should == user
      policy.post.should == Post
    end

    it "returns an instantiated policy given an active model class" do
      policy = Pundit.policy(user, Comment)
      policy.user.should == user
      policy.comment.should == Comment
    end

    it "returns nil if the given policy can't be found" do
      Pundit.policy(user, article).should be_nil
      Pundit.policy(user, Article).should be_nil
    end

    describe "with .policy_class set on the model" do
      it "returns an instantiated policy given a plain model instance" do
        policy = Pundit.policy(user, artificial_blog)
        policy.user.should == user
        policy.blog.should == artificial_blog
      end

      it "returns an instantiated policy given a plain model class" do
        policy = Pundit.policy(user, ArtificialBlog)
        policy.user.should == user
        policy.blog.should == ArtificialBlog
      end

      it "returns an instantiated policy given a plain model instance providing an anonymous class" do
        policy = Pundit.policy(user, article_tag)
        policy.user.should == user
        policy.tag.should == article_tag
      end

      it "returns an instantiated policy given a plain model class providing an anonymous class" do
        policy = Pundit.policy(user, ArticleTag)
        policy.user.should == user
        policy.tag.should == ArticleTag
      end
    end
  end

  describe ".policy!" do
    it "returns an instantiated policy given a plain model instance" do
      policy = Pundit.policy!(user, post)
      policy.user.should == user
      policy.post.should == post
    end

    it "returns an instantiated policy given an active model instance" do
      policy = Pundit.policy!(user, comment)
      policy.user.should == user
      policy.comment.should == comment
    end

    it "returns an instantiated policy given a plain model class" do
      policy = Pundit.policy!(user, Post)
      policy.user.should == user
      policy.post.should == Post
    end

    it "returns an instantiated policy given an active model class" do
      policy = Pundit.policy!(user, Comment)
      policy.user.should == user
      policy.comment.should == Comment
    end

    it "throws an exception if the given policy can't be found" do
      expect { Pundit.policy!(user, article) }.to raise_error(Pundit::NotDefinedError)
      expect { Pundit.policy!(user, Article) }.to raise_error(Pundit::NotDefinedError)
    end
  end

  describe "#verify_authorized" do
    it "does nothing when authorized" do
      controller.authorize(post)
      controller.verify_authorized
    end

    it "raises an exception when not authorized" do
      expect { controller.verify_authorized }.to raise_error(Pundit::NotAuthorizedError)
    end
  end

  describe "#verify_policy_scoped" do
    it "does nothing when policy_scope is used" do
      controller.policy_scope(Post)
      controller.verify_policy_scoped
    end

    it "raises an exception when policy_scope is not used" do
      expect { controller.verify_policy_scoped }.to raise_error(Pundit::NotAuthorizedError)
    end
  end

  describe "#authorize" do
    it "infers the policy name and authorized based on it" do
      controller.authorize(post).should be_true
    end

    it "can be given a different permission to check" do
      controller.authorize(post, :show?).should be_true
      expect { controller.authorize(post, :destroy?) }.to raise_error(Pundit::NotAuthorizedError)
    end

    it "can be given permission to check and parameters" do
      controller.authorize(post, :compare, 1, 1).should be_true
      expect { controller.authorize(post, :compare, 2, 1) }.to raise_error(Pundit::NotAuthorizedError)
    end

    it "works with anonymous class policies" do
      controller.authorize(article_tag, :show?).should be_true
      expect { controller.authorize(article_tag, :destroy?) }.to raise_error(Pundit::NotAuthorizedError)
    end

    it "raises an error when the permission check fails" do
      expect { controller.authorize(Post.new) }.to raise_error(Pundit::NotAuthorizedError)
    end
  end

  describe "#pundit_user" do
    it 'returns the same thing as current_user' do
      controller.pundit_user.should eq controller.current_user
    end
  end

  describe ".policy" do
    it "returns an instantiated policy" do
      policy = controller.policy(post)
      policy.user.should == user
      policy.post.should == post
    end

    it "throws an exception if the given policy can't be found" do
      expect { controller.policy(article) }.to raise_error(Pundit::NotDefinedError)
    end
  end

  describe ".policy_scope" do
    it "returns an instantiated policy scope" do
      controller.policy_scope(Post).should == :published
    end

    it "returns an instantiated custom policy scope" do
      controller.policy_scope(Post, :custom).should == :unpublished
    end

    it "returns an instantiated custom policy scope with parameters" do
      controller.policy_scope(Post, :do_math, 2, 3).should == 5
    end

    it "throws an exception if the given policy can't be found" do
      expect { controller.policy_scope(Article) }.to raise_error(Pundit::NotDefinedError)
    end

    it "throws an exception if the given custom scope can't be found" do
      expect{ controller.policy_scope(Post, :wrong_name) }.to raise_error(NoMethodError)
    end
  end
end
