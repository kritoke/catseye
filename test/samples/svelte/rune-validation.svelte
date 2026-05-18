<script>
  // === BAD: $state without initialization ===
  let uninit = $state();
  
  // === BAD: setInterval without cleanup ===
  $effect(() => {
    setInterval(() => console.log('tick'), 1000);
  });
</script>
