---
layout: default
page_class: writeups-page
collection: writeups
title: Writeups
permalink: /writeups/
---

# Writeups

<!-- Search Bar -->
<div class="search-container">
  <input type="text" id="search-input" placeholder="Search writeups by title or category (e.g., 'htb', 'thm' or 'ctf')..." />
  <div id="search-results-count" class="search-count"></div>
</div>

<div class="grid">
  <div class="writeups-list">
    {% assign sorted_writeups = site.writeups | sort: 'date' | reverse %}
    {% for post in sorted_writeups %}
      <div class="card writeup-item" 
           data-title="{{ post.title | downcase }}" 
           data-categories="{{ post.categories | join: ' ' | downcase }}">
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
</div>

{% if site.writeups.size == 0 %}
  <p>No writeups yet – check back soon!</p>
{% endif %}

<style>
  .search-container {
    margin-bottom: 2rem;
    text-align: center;
  }
  #search-input {
    width: 100%;
    max-width: 500px;
    padding: 0.75rem;
    font-size: 1.1rem;
    border: 2px solid #ddd;
    border-radius: 8px;
    outline: none;
    transition: border-color 0.3s;
  }
  #search-input:focus {
    border-color: #007bff;
  }
  .search-count {
    margin-top: 0.8rem;
    font-style: italic;
    color: #666;
    font-size: 0.95rem;
  }
  .writeup-item {
    transition: opacity 0.2s;
  }
  .writeup-item.hidden {
    display: none !important;
  }
  .grid {
    margin-top: 2rem;
  }
</style>

<!-- JavaScript to filter visible posts based upon the search query given -->
<script>
document.addEventListener('DOMContentLoaded', function() {
  const input = document.getElementById('search-input');
  const items = document.querySelectorAll('.writeup-item');
  const countEl = document.getElementById('search-results-count');

  if (!input || items.length === 0) return;

  input.addEventListener('input', function() {
    const query = this.value.trim().toLowerCase();
    let visibleCount = 0;

    items.forEach(item => {
      const title = item.dataset.title || '';
      const categories = item.dataset.categories || '';

      const matches = title.includes(query) || categories.includes(query);

      if (matches || query === '') {
        item.classList.remove('hidden');
        visibleCount++;
      } else {
        item.classList.add('hidden');
      }
    });

    // Update results count
    if (query) {
      countEl.textContent = visibleCount === items.length 
        ? `All ${visibleCount} writeups` 
        : `Showing ${visibleCount} of ${items.length} writeups`;
    } else {
      countEl.textContent = '';
    }
  });
});
</script>