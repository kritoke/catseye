<script>
  // Svelte 5 rune patterns (correct usage)
  let count = $state(0);
  let doubled = $derived(count * 2);
  
  $effect(() => {
    console.log('count changed:', count);
    return () => console.log('cleanup');
  });
  
  let { name, age = 18 } = $props();
</script>

<p>{name} is {age}</p>
<button onclick={() => count++}>+</button>
