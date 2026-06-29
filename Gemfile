# frozen_string_literal: true

source "https://rubygems.org"

ruby File.read(".ruby-version").strip

git_source(:github) { |repo_name| "https://github.com/dxw/security-alert-notifier" }

gem "standardrb"

group :test do
  gem "minitest"
end

gem "csv"

group :development do
  # keep standard as the top-level linter entrypoint; update to latest available
  gem "standard"
  # optional, only if explicitly pinned today; otherwise let standard resolve these:
  # gem "rubocop"
  # gem "rubocop-ast"
end
