#!/usr/bin/env ruby

require "csv"
require "optparse"
require "net/http"
require "open-uri"
require "json"

options = {}

parser = OptionParser.new { |opts|
  opts.banner = "check_github_vulnerabilities.rb [options]"

  opts.on("-o", "--organization NAME", "The name of the GitHub organization") do |o|
    options[:organization] = o
  end

  opts.on("-t", "--token TOKEN", "A GitHub personal access token") do |t|
    options[:token] = t
  end

  opts.on("-f", "--filter FILTER", "A regex to filter repositories") do |f|
    options[:filter] = f
  end

  opts.on("-c", "--csv FILE", "Write output to FILE in CSV format") do |c|
    options[:csv] = c
  end

  opts.on("-h", "--help", "Prints this help") do
    puts opts
    exit
  end
}

class GitHub
  Result = Struct.new(:repos, :cursor, :more?)
  Repo = Struct.new(:url, :alerts)
  Alert = Struct.new(:package_name, :affected_range, :severity, :fixed_in, :details)

  BASE_URI = "https://api.github.com/graphql".freeze

  def vulnerable_repos
    @vulnerable_repos ||= fetch_vulnerable_repos(repositories)
  end

  def fetch_vulnerable_repos(repositories)
    vulnerable_repos = repositories.select { |repo|
      next if has_govpress_topic?(repo.dig("repositoryTopics", "nodes"))
      next if has_no_vulnerabilityAlerts?(repo.dig("vulnerabilityAlerts", "nodes"))

      repo["vulnerabilityAlerts"]["nodes"].detect { |v| v["dismissedAt"].nil? && v["fixedAt"].nil? }
    }
    return [] unless vulnerable_repos.any?

    build_repository_alerts(vulnerable_repos)
  end

  def build_repository_alerts(vulnerable_repos)
    vulnerable_repos.map do |repo|
      alerts = repo.dig("vulnerabilityAlerts", "nodes").map { |alert|
        if alert.dig("dismissedAt").nil? && alert.dig("fixedAt").nil?
          Alert.new(alert.dig("securityVulnerability", "package", "name"),
            alert.dig("securityVulnerability", "vulnerableVersionRange"),
            alert.dig("securityVulnerability", "severity"),
            alert.dig("securityVulnerability", "firstPatchedVersion", "identifier"),
            alert.dig("securityAdvisory", "summary"))
        end
      }

      url = "https://github.com/#{repo["nameWithOwner"]}"

      Repo.new(url, alerts.compact)
    end
  end

  private

  def has_govpress_topic?(topics)
    return false if topics.empty?
    topics.select { |node| node["topic"].has_value?("govpress") }.any?
  end

  def has_no_vulnerabilityAlerts?(alerts)
    alerts.empty?
  end

  def repositories
    cursor = nil
    repos = []

    uri = URI(BASE_URI)

    _res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http|
      loop do
        result = fetch_repositories(cursor: cursor, http: http)
        repos << result.repos
        cursor = result.cursor
        break unless result.more?
      end
    }

    repos.flatten!
  end

  def fetch_repositories(http:, cursor: nil)
    pagination_params = "first: 100"
    pagination_params += "after: \"#{cursor}\"" if cursor

    query = <<-GRAPHQL
      query vunerableRepos {
        organization(login: "#{ORGANIZATION_NAME}") {
          repositories(#{pagination_params}) {
            pageInfo {
              startCursor
              endCursor
              hasNextPage
            }
            nodes {
              nameWithOwner
              repositoryTopics(first: 10) {
                nodes {
                  topic {
                    name
                  }
                }
              }
              vulnerabilityAlerts(first: 100) {
                nodes {
                  dismissedAt
                  fixedAt
                  securityAdvisory {
                    summary
                  }
                  securityVulnerability {
                    firstPatchedVersion {
                      identifier
                    }
                    package {
                      name
                    }
                    severity
                    vulnerableVersionRange
                  }
                }
              }
            }
          }
        }
      }
    GRAPHQL

    json = JSON.generate(query: query)

    uri = URI(BASE_URI)

    req = Net::HTTP::Post.new(uri)
    req.body = json
    req["Authorization"] = "Bearer #{GITHUB_OAUTH_TOKEN}"
    req["Accept"] = "application/vnd.github.vixen-preview+json"

    res = http.request(req)

    res.value

    body = JSON.parse(res.body)["data"]["organization"]["repositories"]

    Result.new(
      body["nodes"],
      body["pageInfo"]["endCursor"],
      body["pageInfo"]["hasNextPage"]
    )
  end
end

if $PROGRAM_NAME == __FILE__
  parser.parse!

  if options[:token].nil?
    puts "UNKNOWN: Missing GitHub personal access token - usage: #{parser.help}"
    exit 3
  end

  if options[:organization].nil?
    puts "UNKNOWN: Missing GitHub organization name - usage: #{parser.help}"
    exit 3
  end

  ORGANIZATION_NAME = options[:organization].freeze
  GITHUB_OAUTH_TOKEN = options[:token].freeze

  begin
    github = GitHub.new

    if github.vulnerable_repos.any?
      if options[:filter].nil?
        total_vulnerabilities = github.vulnerable_repos.sum { |repo| repo.alerts.length }
        vulnerable_repo_count = github.vulnerable_repos.length
      else
        total_vulnerabilities = 0
        vulnerable_repo_count = 0
        github.vulnerable_repos.each do |repo|
          if options[:filter].nil? || repo.url =~ /#{options[:filter]}/
            vulnerable_repo_count += 1
            repo.alerts.each do |alert|
              total_vulnerabilities += 1
            end
          end
        end
      end

      if vulnerable_repo_count == 0
        puts "OK: No vulnerabilities"
        exit 0
      end

      puts "WARNING: #{total_vulnerabilities} vulnerabilities in #{vulnerable_repo_count} repos"

      csv_data = [["Repository", "Package", "Severity", "Affected range", "Fixed in", "Details"]]

      github.vulnerable_repos.each do |repo|
        if options[:filter].nil? || repo.url =~ /#{options[:filter]}/
          puts repo.url if options[:csv].nil?

          repo.alerts.each do |alert|
            if options[:csv].nil?
              puts "  #{alert.package_name} (#{alert.affected_range})"
              puts "  Severity: #{alert.severity.capitalize}"
              puts "  Fixed in: #{alert.fixed_in}"
              puts "  Details: #{alert.details}"
              puts
            else
              csv_data.append([repo.url,
                alert.package_name,
                alert.severity.capitalize,
                alert.affected_range,
                alert.fixed_in,
                alert.details])
            end
          end
        end
      end

      unless options[:csv].nil?
        CSV.open(options[:csv], "wb", force_quotes: true, headers: true) do |csv|
          csv_data.each do |row|
            csv << row
          end
        end
        puts "Vulnerability data written to: #{options[:csv]}"
      end

      exit 1
    else
      puts "OK: No vulnerabilities"
      exit 0
    end
  rescue => e
    puts "UNKNOWN: #{e}\n#{e.full_message}"
    exit 3
  end
end
