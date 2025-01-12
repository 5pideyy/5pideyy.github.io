# frozen_string_literal: true

source "https://rubygems.org"

# Main dependencies
gem "jekyll", "~> 4.3.0"
gem "jekyll-theme-chirpy", "~> 7.2", ">= 7.2.2"

# Development and Test dependencies
group :development, :test do
  gem "html-proofer", "~> 5.0"
  gem "nokogiri", "~> 1.18", ">= 1.18.1" # Required for HTML parsing and manipulation
  gem "typhoeus", "~> 1.4" # Required for making HTTP requests in html-proofer
  gem "rainbow", "~> 3.1" # For colored output in html-proofer
  gem "pdf-reader", "~> 2.13" # Handles PDF processing
  gem "zeitwerk", "~> 2.7" # Autoloading framework
end

# Windows-specific dependencies
platforms :mingw, :x64_mingw, :mswin do
  gem "tzinfo", ">= 1", "< 3" # Time zone information for Windows
  gem "tzinfo-data" # Additional time zone data for Windows
  gem "wdm", "~> 0.2.0" # File watcher for Windows
end

# Plugins and optional dependencies
gem "json", "~> 2.9" # JSON handling
gem "ethon", "~> 0.16" # Curl wrapper for Typhoeus
gem "racc", "~> 1.8" # Parser runtime for Ruby
gem "afm", "~> 0.2" # Adobe Font Metrics
gem "Ascii85", "~> 2.0" # ASCII encoding
gem "ruby-rc4", "~> 0.1.5" # RC4 encryption
gem "ttfunk", "~> 1.8" # Font handling library

# Optional: Add any additional gems specific to your project here

