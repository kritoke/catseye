<script>
  // === BAD: $state without initialization ===
  let uninit = $state();
  
  // === BAD: setInterval without cleanup ===
  $effect(() => {
    setInterval(() => console.log('tick'), 1000);
  });
  
  // === BAD: $derived reassignment ===
  let doubled = $derived(count * 2);
  doubled = 42;
</script>
