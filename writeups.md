---
layout: default
page_class: writeups-page
collection: writeups
title: Writeups
permalink: /writeups/
---

# Writeups

<div class="grid">
  {% assign sorted_writeups = site.writeups | sort: 'date' | reverse %}
  {% for post in sorted_writeups %}
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
        <a href="{{ post.url }}" class="card-link">Read writeup →</a>
      </p>
    </div>
  {% endfor %}
</div>

{% if site.writeups.size == 0 %}
  <p>No writeups yet – check back soon!</p>
{% endif %}