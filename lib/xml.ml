type node =
  | E of string * attr list * node list
  | P of string
and attr = (string * string) * string

let xml_of_string s =
  (* we drop the namespace part of the element here *)
  let el ((ns, name), atts) kids = E (name, atts, kids) in
  let data d = P d in
  let input = Xmlm.make_input ~strip:true (`String (0,s)) in
  let _, node = Xmlm.input_doc_tree ~el ~data input in
  node

let frag = function
  | E (name, attrs, kids) -> `El ((("", name), attrs), kids)
  | P d -> `Data d

let string_of_xml x =
  let buf = Buffer.create 100 in
  let output = Xmlm.make_output (`Buffer buf) in
  Xmlm.output_doc_tree frag output (None, x);
  Buffer.contents buf

(* select node *)
let find_node =
  let rec search tree path = 
    match (tree, path) with
    | tree, [] -> Some tree
    | [], _ -> None
    | E (name, _, tree) :: _, elem :: path when elem = name ->
      search tree path
    | _ :: tree, path -> search tree path
  in
  let regexp = Str.regexp "/" in 
  fun node path -> search node (Str.split regexp path)
  

let find_property node path =
  match find_node node path with
  | Some [P property] -> Some property
  | _ -> None

