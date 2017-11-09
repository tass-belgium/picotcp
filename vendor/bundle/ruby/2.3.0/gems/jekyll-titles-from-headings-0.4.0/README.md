# Jekyll Title from Headings

*A Jekyll plugin to pull the page title from the first Markdown heading when none is specified.*

[![Build Status](https://travis-ci.org/benbalter/jekyll-title-from-headings.svg?branch=master)](https://travis-ci.org/benbalter/jekyll-title-from-headings)

## What it does

If you have a Jekyll page that doesn't have a title specified in the YAML Front Matter, but the first non-whitespace line in the page is a Markdown H1 / H2 / H3, this plugin instructs Jekyll to use that first heading as the page's title.

## Why

Because lots of plugins and templates rely on `page.title`.

If you're using a plugin like [Jekyll Optional Front Matter](https://github.com/benbalter/jekyll-optional-front-matter), you'd have to add Front Matter, just to get the title, which you're already specifying in the document.

Additionally, this allows you to store the title semantically, in the document itself so that it's readable, both as Markdown and when rendered, as machine-readable for plugins like [Jekyll SEO Tag](https://github.com/benbalter/jekyll-seo-tag).

## Usage

1. Add the following to your site's Gemfile:

  ```ruby
  gem 'jekyll-titles-from-headings'
  ```

2. Add the following to your site's config file:

  ```yml
  gems:
    - jekyll-titles-from-headings
  ```
