# MalDNS
*used in combination with a server to redirect requests to.*
___

# Showcase
![screenshot 1](https://github.com/389850689/MalDNS/blob/main/assets/screenshot1.png?raw=true)
```rust
 response.answers
         .iter_mut()
         .for_each(|r| r.data = u32::to_be_bytes(0x7F_00_00_01).into());
```
![screenshot 2](https://github.com/389850689/MalDNS/blob/main/assets/screenshot2.png?raw=true)
