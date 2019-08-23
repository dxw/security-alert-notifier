require 'net/http'
require 'open-uri'
require 'json'

if ARGV[0].nil?
  puts 'Missing GitHub personal access token - usage: `ruby check_github_vulnerabilities.rb <access_token>`'
  exit 3
else
  GITHUB_OAUTH_TOKEN = ARGV[0].freeze
end

class GitHub
  Result = Struct.new(:repos, :cursor, :more?)

  BASE_URI = 'https://api.github.com/graphql'.freeze

  def vulnerabilities
    vulnerable_repos = repositories.select do |repo|
      next if repo['vulnerabilityAlerts']['nodes'].empty?

      repo['vulnerabilityAlerts']['nodes'].detect { |v| v['dismissedAt'].nil? }
    end

    vulnerable_repos.each do |repo|
      puts "https://github.com/#{repo['nameWithOwner']}"

      repo['vulnerabilityAlerts']['nodes'].each do |alert|
        puts "  #{alert['packageName']} (#{alert['affectedRange']})"
        puts "  Fixed in: #{alert['fixedIn']}"
        puts "  Details: #{alert['externalReference']}"
        puts
      end
    end
  end

  private

  def repositories
    cursor = nil
    repos = []

    loop do
      result = fetch_repositories(cursor: cursor)
      repos << result.repos
      cursor = result.cursor
      break unless result.more?
    end

    repos.flatten!
  end


  def fetch_repositories(cursor: nil)
    pagination_params = 'first: 25'
    pagination_params += "after: \"#{cursor}\"" if cursor

    query = <<-GRAPHQL
      query {
        organization(login: dxw) {
          repositories(isFork:false #{pagination_params}) {
            pageInfo {
              startCursor
              endCursor
              hasNextPage
            }
            nodes {
              nameWithOwner
              vulnerabilityAlerts(first: 10) {
                nodes {
                  packageName
                  affectedRange
                  externalReference
                  fixedIn
                  dismissedAt
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

    res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
      http.request(req)
    end

    body = JSON.parse(res.body)['data']['organization']['repositories']

    Result.new(
      body['nodes'],
      body['pageInfo']['endCursor'],
      body['pageInfo']['hasNextPage']
    )
  end
end

GitHub.new.vulnerabilities

