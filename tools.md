---
layout: default
page_class: tools-page
collection: tools
title: Tools
permalink: /tools/
---

# Custom Tools

<div class="grid">
  {% assign sorted_tools = site.tools | sort: 'date' | reverse %}
  {% for post in sorted_tools %}
    <div class="card">
      <h3><a href="{{ post.url }}">{{ post.title }}</a></h3>
      
      <p class="post-meta" style="margin: 0.5rem 0; opacity: 0.8; font-size: 0.9rem;">
        {{ post.date | date: "%B %d, %Y" }}
        {% if post.categories %}
          • {{ post.categories | join: " • " | upcase }}
        {% endif %}
      </p>

      {% if post.excerpt and post.excerpt != empty %}
        <p style="margin: 1rem 0 0 0;">{{ post.excerpt | strip_html | truncate: 140 }}</p>
      {% endif %}

      <p style="margin-top: 1rem;">
        <a href="{{ post.url }}" class="card-link">View Tool →</a>
      </p>
    </div>
  {% endfor %}
</div>

{% if site.tools.size == 0 %}
  <p>No tools yet – check back soon!</p>
{% endif %}