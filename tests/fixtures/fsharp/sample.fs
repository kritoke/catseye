// tests/fixtures/fsharp/sample.fs — representative F# file for the spike
module Sample

open System
open System.IO

// ── records ────────────────────────────────────────────────────

type User = {
    Name: string
    Email: string
    Age: int
}

type Config = {
    Host: string
    Port: int
    Debug: bool
}

// ── discriminated union ────────────────────────────────────────

type Shape =
    | Circle of radius: float
    | Rectangle of width: float * height: float
    | Triangle of b: float * h: float

// ── simple bindings ────────────────────────────────────────────

let greeting = "Hello, world!"
let pi = 3.14159
let isReady = true

// ── function with pattern matching ─────────────────────────────

let describeShape shape =
    match shape with
    | Circle r -> sprintf "Circle with radius %f" r
    | Rectangle (w, h) -> sprintf "Rectangle %fx%f" w h
    | Triangle (b, h) -> sprintf "Triangle base=%f height=%f" b h

// ── function with let binding + control flow ───────────────────

let validateUser (user: User) =
    let nameLen = user.Name.Length
    if nameLen < 1 then
        Error "Name is required"
    else if not (user.Email.Contains("@")) then
        Error "Invalid email"
    else
        Ok user

// ── tuple ──────────────────────────────────────────────────────

let swap (a, b) = (b, a)

// ── lambda ─────────────────────────────────────────────────────

let add = fun x y -> x + y

// ── list ───────────────────────────────────────────────────────

let numbers = [1; 2; 3; 4; 5]
let doubled = numbers |> List.map (fun n -> n * 2)

// ── record construction + update ───────────────────────────────

let defaultConfig = {
    Host = "localhost"
    Port = 8080
    Debug = false
}

let debugConfig = { defaultConfig with Debug = true }

// ── type with member ───────────────────────────────────────────

type Counter =
    { Value: int }
    member this.Increment() = { Value = this.Value + 1 }
    member this.Add(n) = { Value = this.Value + n }

// ── real taint path: Console.ReadLine → File.WriteAllText ──────

let saveUserInput () =
    let input = Console.ReadLine()
    File.WriteAllText("/tmp/output.txt", input)

// ── real taint path: argv → printf ─────────────────────────────

let printArgs () =
    let args = Environment.GetCommandLineArgs()
    for arg in args do
        printfn "arg: %s" arg

// ── skip_calls: ignore ─────────────────────────────────────────

let ignored () =
    let result = Console.ReadLine()
    ignore result

// ── computation expression (async) ─────────────────────────────

let fetchDataAsync url = async {
    let! data = async { return "mock data" }
    return data.Length
}

// ── entry point ────────────────────────────────────────────────

[<EntryPoint>]
let main argv =
    printfn "%s" greeting
    let user = { Name = "Alice"; Email = "alice@example.com"; Age = 30 }
    match validateUser user with
    | Ok u -> printfn "Valid: %s" u.Name
    | Error msg -> printfn "Error: %s" msg
    saveUserInput ()
    printArgs ()
    0
