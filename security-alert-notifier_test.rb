require "minitest/autorun"
require_relative "security-alert-notifier"

describe GitHub do
  describe "when the repository has no topics" do
    it "is included in the list" do
      github = GitHub.new
      result = github.fetch_vulnerable_repos([repo_with_no_topics])
      _(result.size).must_equal 1
    end
  end

  describe "when the repository has topics but none are 'govpress'" do
    it "is included in the list" do
      github = GitHub.new
      result = github.fetch_vulnerable_repos([repo_with_topics])
      _(result.size).must_equal 1
    end
  end

  describe "when the repository has topics and one is 'govpress'" do
    it "is not included in the list" do
      github = GitHub.new
      result = github.fetch_vulnerable_repos([repo_with_govpress_topic])
      _(result).must_equal []
    end
  end

  describe "when the repository has no dismissed alerts" do
    it "is included in the list" do
      github = GitHub.new
      result = github.fetch_vulnerable_repos([repo_with_no_topics])
      _(result.size).must_equal 1
    end
  end

  describe "when the repository has only dismissed alerts" do
    it "is not included in the list" do
      github = GitHub.new
      result = github.fetch_vulnerable_repos([repo_with_only_dismissed_alerts])
      _(result.size).must_equal 0
    end
  end

  describe "when the repository has some active alerts and some dismissed alerts" do
    it "is included in the list" do
      github = GitHub.new
      result = github.fetch_vulnerable_repos([repo_with_active_and_dismissed_alerts])
      _(result.size).must_equal 1
    end
  end

  describe "when a vulnerability alert does not have the attribute" do
    it "does not blow up" do
      github = GitHub.new
      vulnerable_repos = [{"vulnerabilityAlerts" => {"nodes" => [securityVulnerability_with_missing_attribute]}}]
      result = github.build_repository_alerts(vulnerable_repos)
      _(result.first).must_be_instance_of GitHub::Repo
    end

    it "return nil in the alert for the missin attribute" do
      github = GitHub.new
      vulnerable_repos = [{"vulnerabilityAlerts" => {"nodes" => [securityVulnerability_with_missing_attribute]}}]
      result = github.build_repository_alerts(vulnerable_repos).first.alerts.first
      _(result.details).must_be_nil
    end
  end

  describe "when the vulnerability is well formed" do
    it "a valid alert" do
      github = GitHub.new
      vulnerable_repos = [{"vulnerabilityAlerts" => {"nodes" => [valid_securityVulnerability]}}]
      result = github.build_repository_alerts(vulnerable_repos).first.alerts.first
      _(result.package_name).must_equal "Package Name"
      _(result.affected_range).must_equal "A range of things"
      _(result.fixed_in).must_equal "IDENTIFIER"
      _(result.details).must_equal "This is the summary"
    end
  end

  describe "when there are no repos" do
    it "returns an empty array" do
      github = GitHub.new
      github.fetch_vulnerable_repos([]).must_equal []
    end
  end

  describe "when there are no repos with alerts" do
    it "returns an empty array" do
      github = GitHub.new
      result = github.fetch_vulnerable_repos([repo_without_alerts])
      _(result).must_equal []
    end
  end
end

def repo_with_no_topics
  {
    "nameWithOwner" => "dxw/repo",
    "repositoryTopics" => {
      "nodes" => []
    },
    "vulnerabilityAlerts" => {
      "nodes" => [valid_securityVulnerability]
    }
  }
end

def repo_with_topics
  {
    "nameWithOwner" => "dxw/repo",
    "repositoryTopics" => {
      "nodes" => [other_topic]
    },
    "vulnerabilityAlerts" => {
      "nodes" => [valid_securityVulnerability]
    }
  }
end

def repo_with_govpress_topic
  {
    "nameWithOwner" => "dxw/repo",
    "repositoryTopics" => {
      "nodes" => [other_topic, govpress_topic]
    },
    "vulnerabilityAlerts" => {
      "nodes" => [valid_securityVulnerability]
    }
  }
end

def other_topic
  {
    "topic" => {
      "name" => "other"
    }
  }
end

def govpress_topic
  {
    "topic" => {
      "name" => "govpress"
    }
  }
end

def securityVulnerability_with_missing_attribute
  {
    "securityVulnerability" => {
      "package" => {
        "name" => "Package Name"
      },
      "vulnerableVersionRange" => "A range of things",
      "firstPatchedVersion" => {
        "identifier" => "IDENTIFIER"
      }
    }
  }
end

def valid_securityVulnerability
  {
    "securityVulnerability" => {
      "package" => {
        "name" => "Package Name"
      },
      "vulnerableVersionRange" => "A range of things",
      "firstPatchedVersion" => {
        "identifier" => "IDENTIFIER"
      }
    },
    "securityAdvisory" => {
      "summary" => "This is the summary"
    }
  }
end

def dismissed_securityVulnerability
  {
    "dismissedAt" => "2021-01-01T-15:50+00",
    "securityVulnerability" => {
      "package" => {
        "name" => "Package Name"
      },
      "vulnerableVersionRange" => "A range of things",
      "firstPatchedVersion" => {
        "identifier" => "IDENTIFIER"
      }
    },
    "securityAdvisory" => {
      "summary" => "This is the summary"
    }
  }
end

def repo_without_alerts
  {
    "nameWithOwner" => "dxw/repo",
    "repositoryTopics" => {
      "nodes" => [other_topic]
    },
    "vulnerabilityAlerts" => {
      "nodes" => []
    }
  }
end

def repo_with_only_dismissed_alerts
  {
    "nameWithOwner" => "dxw/repo",
    "repositoryTopics" => {
      "nodes" => []
    },
    "vulnerabilityAlerts" => {
      "nodes" => [dismissed_securityVulnerability]
    }
  }
end

def repo_with_active_and_dismissed_alerts
  {
    "nameWithOwner" => "dxw/repo",
    "repositoryTopics" => {
      "nodes" => []
    },
    "vulnerabilityAlerts" => {
      "nodes" => [valid_securityVulnerability, dismissed_securityVulnerability]
    }
  }
end
