require 'dotenv/load'
require 'typhoeus'
require 'pry'
require 'json'

print 'Fetching vulnerable repositories'

Result = Struct.new(:repos, :cursor, :more?)

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
            vulnerabilityAlerts(first: 3) {
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

  request = Typhoeus.post(
    'https://api.github.com/graphql',
    body: json,
    headers: {
      'Authorization': "Bearer #{ENV['GITHUB_OAUTH_TOKEN']}",
      'Accept': 'application/vnd.github.vixen-preview+json'
    }
  )

  body = JSON.parse(request.body)

  binding.pry if body['errors']

  body = body['data']['organization']['repositories']

  Result.new(body['nodes'], body['pageInfo']['endCursor'], body['pageInfo']['hasNextPage'])
end

cursor = nil
repos = []

loop do
  print '.'

  result = fetch_repositories(cursor: cursor)
  repos << result.repos
  cursor = result.cursor
  break unless result.more?
end

puts
puts

repos.flatten!

vulnerable_repos = repos.select do |repo|
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

