<script>
  import { writable } from 'svelte/store';
  import { derived } from 'svelte/store';
  
  // Svelte 4 stores - should migrate to runes
  const count = writable(0);
  const doubled = derived(count, $count => $count * 2);
  
  function increment() {
    count.update(n => n + 1);
  }
  
  // XSS: user-provided HTML rendered directly
  let userHtml = '<img src=x onerror=alert(1)>';
</script>

<button on:click={increment}>
  Count: {$count}
</button>

{@html userHtml}
