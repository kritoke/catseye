<script>
  // React patterns that don't exist in Svelte
  const [state, setState] = useState(0);
  useEffect(() => { console.log('effect'); }, []);
  const ref = useRef(null);
  const memo = useMemo(() => state * 2, [state]);
</script>

<div ref={ref}>{state}</div>
<button onClick={() => setState(s => s + 1)}>Increment</button>
