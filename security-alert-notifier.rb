#!/usr/bin/env ruby

require "cgi"
require "csv"
require "date"
require "optparse"
require "net/http"
require "open-uri"
require "json"

# We aim to close vulnerability alerts within SLA_IN_DAYS days. In this script,
# we count all calendar days, including weekends and bank holidays.
SLA_IN_DAYS = 14

options = {}

parser = OptionParser.new { |opts|
  opts.banner = "check_github_vulnerabilities.rb [options]"

  opts.on("-o", "--organization NAME", "The name of the GitHub organization") do |o|
    options[:organization] = o
  end

  opts.on("-t", "--token TOKEN", "A GitHub personal access token") do |t|
    options[:token] = t
  end

  opts.on("-i", "--include [TOPIC]", Array, "A comma-separated list of repository topics to include") do |i|
    options[:included_topics] = i
  end

  opts.on("-e", "--exclude [TOPIC]", Array, "A comma-separated list of repository topics to exclude") do |e|
    options[:excluded_topics] = e
  end

  opts.on("-f", "--filter FILTER", "A regex to filter repositories by name") do |f|
    options[:filter] = f
  end

  opts.on("-c", "--csv FILE", "Write output to FILE in CSV format") do |c|
    options[:csv] = c
  end

  opts.on("-h", "--html", "Write HTML output to STDOUT") do
    options[:html] = "STDOUT"
  end

  opts.on("-h", "--help", "Prints this help") do
    puts opts
    exit
  end
}

class GitHub
  Result = Struct.new(:repos, :cursor, :more?)
  Repo = Struct.new(:url, :alerts)
  Alert = Struct.new(:package_name, :affected_range, :severity, :created_at, :fixed_in, :details)

  BASE_URI = "https://api.github.com/graphql".freeze

  def initialize(included_topics = [], excluded_topics = [])
    @included_topics = included_topics.nil? ? [] : included_topics
    @excluded_topics = excluded_topics.nil? ? [] : excluded_topics
  end

  def vulnerable_repos
    @vulnerable_repos ||= fetch_vulnerable_repos(repositories)
  end

  def fetch_vulnerable_repos(repositories)
    vulnerable_repos = repositories.select { |repo|
      next if has_skippable_topics?(repo.dig("repositoryTopics", "nodes"))
      next if has_no_vulnerabilityAlerts?(repo.dig("vulnerabilityAlerts", "nodes"))

      repo["vulnerabilityAlerts"]["nodes"].detect { |v| alert_is_active?(v) }
    }
    return [] unless vulnerable_repos.any?

    build_repository_alerts(vulnerable_repos)
  end

  def build_repository_alerts(vulnerable_repos)
    vulnerable_repos.map do |repo|
      alerts = repo.dig("vulnerabilityAlerts", "nodes").map { |alert|
        if alert_is_active?(alert)
          Alert.new(alert.dig("securityVulnerability", "package", "name"),
            alert.dig("securityVulnerability", "vulnerableVersionRange"),
            alert.dig("securityVulnerability", "severity"),
            alert.dig("createdAt"),
            alert.dig("securityVulnerability", "firstPatchedVersion", "identifier"),
            alert.dig("securityAdvisory", "summary"))
        end
      }

      url = "https://github.com/#{repo["nameWithOwner"]}"

      Repo.new(url, alerts.compact)
    end
  end

  private

  def alert_is_active?(alert)
    alert.dig("dismissedAt").nil? && alert.dig("fixedAt").nil? && alert.dig("autoDismissedAt").nil?
  end

  def has_skippable_topics?(repo_topics)
    return true if @included_topics.any? && !has_filtered_topics?(repo_topics, @included_topics)
    return true if @excluded_topics.any? && has_filtered_topics?(repo_topics, @excluded_topics)
    false
  end

  def has_filtered_topics?(repo_topics, filtered_topics)
    return false if repo_topics.empty?
    repo_topics.select { |node| filtered_topics.intersection(node["topic"].values).any? }.any?
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
                  createdAt
                  autoDismissedAt
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

def time_to_sla_breach(alert_created_at)
  SLA_IN_DAYS - (Date.today - Date.parse(alert_created_at)).to_i
end

def print_alert_table(alerts)
  puts <<~HEREDOC
    <table style="width: 90%; border-collapse: collapse; border-spacing: 5px; display: block; text-align: left;">
      <thead>
      <tr>
        <th style="padding: 4px 6px;">Package</th>
        <th style="padding: 4px 6px;">Severity</th>
        <th style="padding: 4px 6px;">SLA breach (days)</th>
        <th style="padding: 4px 6px;">Fixed in version</th>
        <th style="padding: 4px 6px;">Details</th>
      </tr>
      </thead>
      <tbody>
  HEREDOC
  alerts.each do |alert|
    puts <<~HEREDOC
      <tr>
        <td style="padding: 4px 6px; white-space: pre;">#{CGI.escapeHTML(alert.package_name)} (#{CGI.escapeHTML(alert.affected_range)})</td>
        <td style="padding: 4px 6px;">#{alert.severity.capitalize}</td>
        <td style="padding: 4px 6px; white-space: pre;">#{time_to_sla_breach(alert.created_at)}</td>
        <td style="padding: 4px 6px;">#{alert.fixed_in}</td>
        <td style="padding: 4px 6px;">#{alert.details}</td>
      </tr>
    HEREDOC
  end
  puts <<~HEREDOC
      </tbody>
    </table>
  HEREDOC
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
    github = GitHub.new(options[:included_topics].freeze, options[:excluded_topics].freeze)

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

      if options[:html].nil?
        puts "WARNING: #{total_vulnerabilities} vulnerabilities in #{vulnerable_repo_count} repos"
      else
        puts "<h3>WARNING: #{total_vulnerabilities} vulnerabilities in #{vulnerable_repo_count} repos</h3>"
      end

      csv_data = [["Repository", "Package", "Severity", "Calendar days to SLA breach", "Affected range", "Fixed in", "Details"]]

      github.vulnerable_repos.each do |repo|
        if options[:filter].nil? || repo.url =~ /#{options[:filter]}/

          puts repo.url if options[:csv].nil? && options [:html].nil?
          if !options[:html].nil?
            puts "<h4><a href=\"#{repo.url}\">#{repo.url}</a></h4>"
            print_alert_table(repo.alerts)
          elsif !options[:csv].nil?
            repo.alerts.each do |alert|
              csv_data.append([repo.url,
                alert.package_name,
                alert.severity.capitalize,
                time_to_sla_breach(alert.created_at),
                alert.affected_range,
                alert.fixed_in,
                alert.details])
            end
          else
            repo.alerts.each do |alert|
              puts "  #{alert.package_name} (#{alert.affected_range})"
              puts "  Severity: #{alert.severity.capitalize}"
              puts "  SLA breach in: #{time_to_sla_breach(alert.created_at)} calendar days"
              puts "  Fixed in: #{alert.fixed_in}"
              puts "  Details: #{alert.details}"
              puts
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
