require "minitest/autorun"
require_relative "security-alert-notifier"

describe GitHub do
  describe "the GitHub class can be tested" do
    it "can be instantiated without running" do
      github = GitHub.new
      assert_instance_of GitHub, github
    end
  end
end
