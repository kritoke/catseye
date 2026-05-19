fn fetch_all(id) {
  fetch_user(id, fn(user) {
    fetch_orders(user.id, fn(orders) {
      fetch_items(orders, fn(items) {
        render(items)
      })
    })
  })
}

fn simple_case(id) {
  let x = 1
  x + 2
}