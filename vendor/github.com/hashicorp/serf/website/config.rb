set :base_url, "https://www.serfdom.io/"

activate :hashicorp do |h|
  h.name        = "serf"
  h.version     = "0.7.0"
  h.github_slug = "hashicorp/serf"
end

helpers do
  # This helps by setting the "active" class for sidebar nav elements
  # if the YAML frontmatter matches the expected value.
  def sidebar_current(expected)
    current = current_page.data.sidebar_current
    if current.start_with?(expected)
      return " class=\"active\""
    else
      return ""
    end
  end
end
