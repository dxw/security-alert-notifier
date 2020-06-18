require "minitest/autorun"
require_relative "security-alert-notifier"

describe GitHub do
  describe "when a vulnerability alert does not have the attribute" do
    it "does not blow up" do
      github = GitHub.new
      vulnerable_repos = [{ "vulnerabilityAlerts" => { "nodes" => [node_with_missting_attribute] }}]
      result = github.build_repository_alerts(vulnerable_repos)
      _(result.first).must_be_instance_of GitHub::Repo
    end

    it "return nil in the alert for the missin attribute" do
      github = GitHub.new
      vulnerable_repos = [{ "vulnerabilityAlerts" => { "nodes" => [node_with_missting_attribute] }}]
      result = github.build_repository_alerts(vulnerable_repos).first.alerts.first
      _(result.details).must_be_nil
    end
  end

  describe "when the vulnerability is well formed" do
    it "a valid alert" do
      github = GitHub.new
      vulnerable_repos = [{ "vulnerabilityAlerts" => { "nodes" => [valid_node] }}]
      result = github.build_repository_alerts(vulnerable_repos).first.alerts.first
      _(result.package_name).must_equal "Package Name"
      _(result.affected_range).must_equal "A range of things"
      _(result.fixed_in).must_equal "IDENTIFIER"
      _(result.details).must_equal "This is the summary"
    end
  end
end

def node_with_missting_attribute
  {
    "securityVulnerability" => {
      "package" => {
        "name" => "Package Name"
      },
      "vulnerableVersionRange" => "A range of things",
      "firstPatchedVersion" => {
        "identifier" =>  "IDENTIFIER"
      }
    }
  }
end

def valid_node
  {
    "securityVulnerability" => {
      "package" => {
        "name" => "Package Name"
      },
      "vulnerableVersionRange" => "A range of things",
      "firstPatchedVersion" => {
        "identifier" =>  "IDENTIFIER"
      }
    },
    "securityAdvisory" => {
      "summary" => "This is the summary"
      }
  }
end

