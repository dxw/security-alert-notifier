#!/usr/bin/env ruby

require 'optparse'
require 'net/http'
require 'open-uri'
require 'json'

options = {}

parser = OptionParser.new do |opts|
  opts.banner = 'check_github_vulnerabilities.rb [options]'

  opts.on("-o", "--organization NAME", "The name of the GitHub organization") do |o|
    options[:organization] = o
  end

  opts.on("-t", "--token TOKEN", "A GitHub personal access token") do |t|
    options[:token] = t
  end

  opts.on("-h", "--help", "Prints this help") do
    puts opts
    exit
  end
end

class GitHub
  Result = Struct.new(:repos, :cursor, :more?)
  Repo = Struct.new(:url, :alerts)
  Alert = Struct.new(:package_name, :affected_range, :fixed_in, :details)

  BASE_URI = 'https://api.github.com/graphql'.freeze

  def vulnerable_repos
    @vulnerable_repos ||= fetch_vulnerable_repos
  end

  def fetch_vulnerable_repos
    vulnerable_repos = repositories.select do |repo|
      next if repo['vulnerabilityAlerts']['nodes'].empty?

      repo['vulnerabilityAlerts']['nodes'].detect { |v| v['dismissedAt'].nil? }
    end
    build_repository_alerts(vulnerable_repos) if vulnerable_repos.any?
  end

  def build_repository_alerts(vulnerable_repos)
      vulnerable_repos.map do |repo|
        alerts = repo.dig("vulnerabilityAlerts", "nodes").map do |alert|
          Alert.new(alert.dig("securityVulnerability", "package", "name"),
                    alert.dig("securityVulnerability", "vulnerableVersionRange"),
                    alert.dig("securityVulnerability", "firstPatchedVersion", "identifier"),
                    alert.dig("securityAdvisory", "summary"))
        end

        url = "https://github.com/#{repo['nameWithOwner']}"

        Repo.new(url, alerts)
      end
  end

  private

  def repositories
    cursor = nil
    repos = []

      uri = URI(BASE_URI)

      res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
        loop do
          result = fetch_repositories(cursor: cursor, http: http)
          repos << result.repos
          cursor = result.cursor
          break unless result.more?
        end
      end

    repos.flatten!
  end

  def fetch_repositories(cursor: nil, http:)
    pagination_params = 'first: 100'
    pagination_params += "after: \"#{cursor}\"" if cursor

    query = <<-GRAPHQL
      query {
        organization(login: \"#{ORGANIZATION_NAME}\") {
          repositories(#{pagination_params}) {
            pageInfo {
              startCursor
              endCursor
              hasNextPage
            }
            nodes {
              nameWithOwner
              vulnerabilityAlerts(first: 100) {
                nodes {
                  dismissedAt
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

    req                  = Net::HTTP::Post.new(uri)
    req.body             = json
    req['Authorization'] = "Bearer #{GITHUB_OAUTH_TOKEN}"
    req['Accept']        = 'application/vnd.github.vixen-preview+json'

    res = http.request(req)

    res.value

    body = JSON.parse(res.body)['data']['organization']['repositories']

    Result.new(
      body['nodes'],
      body['pageInfo']['endCursor'],
      body['pageInfo']['hasNextPage']
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
      total_vulnerabilities = github.vulnerable_repos.sum { |repo| repo.alerts.length }
      puts "WARNING: #{total_vulnerabilities} vulnerabilities in #{github.vulnerable_repos.length} repos"

      github.vulnerable_repos.each do |repo|
        puts repo.url

        repo.alerts.each do |alert|
          puts "  #{alert.package_name} (#{alert.affected_range})"
          puts "  Fixed in: #{alert.fixed_in}"
          puts "  Details: #{alert.details}"
          puts
        end
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
