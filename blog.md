---
layout: default
page_class: blog-page
title: Posts
permalink: /blog/
---

# Posts

<div class="grid">
  {% assign sorted_posts = site.posts | sort: 'date' | reverse %}
  {% for post in sorted_posts %}
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
        <a href="{{ post.url }}" class="card-link">Read post →</a>
      </p>
    </div>
  {% endfor %}
</div>

{% if site.posts.size == 0 %}
  <p>No posts yet – check back soon!</p>
{% endif %}