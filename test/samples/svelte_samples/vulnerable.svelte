<script>
  import { fetch } from './api';
  
  export let userUrl = '';
  
  $: data = fetch(userUrl);
  
  function handleClick(url) {
    eval(url);
  }
</script>

<button on:click={() => handleClick(userUrl)}>
  Click me
</button>

{@html userContent}

{#if showData}
  <p>{data}</p>
{/if}

<style>
  button { color: blue; }
</style>
