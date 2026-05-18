<script>
  let userContent = 'some html content';
  let safeContent = '<p>Safe paragraph</p>';
</script>

<!-- XSS via {@html} with dynamic content -->
{@html userContent}

<!-- Safe: static content -->
{@html safeContent}

<!-- Potential XSS: dynamic but needs context -->
{@html getContent()}
