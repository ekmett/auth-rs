use derivative::{self,Derivative};
use digest::Output;
use hex;
use serde_json;
use serde::ser::{Serialize, Serializer};
use serde::de::{Deserialize, DeserializeOwned, Deserializer, Visitor};
use sha1::{Digest, Sha1};
use std::{
  fmt::{self, Display},
  marker::PhantomData,
  slice,
  vec::Vec,
};

// approximately [u8;20]
type HashCode = Output<Sha1>;

fn hash_str(string: &str) -> HashCode {
  let mut h = Sha1::default();
  h.update(string);
  h.finalize()
}

// compute a hash code of the data structure
fn hash<A:Serialize>(value: &A) -> HashCode {
  hash_str(&serde_json::to_string(value).unwrap())
}


#[derive(Debug,Copy,Clone,Derivative)]
#[derivative(Hash,PartialEq,Eq,PartialOrd,Ord)]
pub struct Proof<A> {
  #[derivative(Hash="ignore",PartialEq="ignore",PartialOrd="ignore")]
  value: Option<A>,
  hash:  HashCode
}

impl <A> Display for Proof<A> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    hex::encode(self.hash).fmt(f)
  }
}

impl <A> Serialize for Proof<A> {
  fn serialize<S>(&self,s:S) -> Result<S::Ok, S::Error> where
    S: Serializer,
  {
    s.serialize_str(&hex::encode(self.hash))
  }
}

struct ProofVisitor<A>(PhantomData<*mut A>);

impl<'de,A> Visitor<'de> for ProofVisitor<A> {
    type Value = Proof<A>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a proof")
    }

    fn visit_str<E>(self, h: &str) -> Result<Self::Value, E> where
      E: serde::de::Error,
    {
      let v = hex::decode(h).unwrap();
      Ok(
        Proof {
          value: None,
          hash: HashCode::from(<[u8;20]>::try_from(v).unwrap())
      })
    }
}

impl <'de,A> Deserialize<'de> for Proof<A> {
  fn deserialize<D>(d:D) -> Result<Self, D::Error> where
    D: Deserializer<'de> {
    d.deserialize_str(ProofVisitor(PhantomData))
  }
}

pub trait Db where {
  fn auth<A : Serialize + DeserializeOwned>(&mut self, a:A) -> Proof<A>;
  fn unauth<A : Serialize + DeserializeOwned>(&mut self, p: Proof<A>) -> A;
}

#[derive(Debug,Clone)]
pub struct Prover { tape: Vec<String> }

impl Prover {
  pub fn new() -> Self { Prover { tape: Vec::new() } }
  pub fn verify(&self) -> Verifier<'_> {
    Verifier(self.tape.iter())
  }
}

impl Db for Prover {
  fn auth<A : Serialize + DeserializeOwned>(&mut self, a:A) -> Proof<A>{
    let h = hash(&a);
    Proof { value: Some(a), hash: h }
  }
  fn unauth<A : Serialize + DeserializeOwned>(&mut self, p: Proof<A>) -> A {
    let r = p.value.unwrap();
    self.tape.push(serde_json::to_string(&r).unwrap());
    r
  }
}

#[derive(Debug,Clone)]
pub struct Verifier<'at>(slice::Iter<'at,String>);

impl <'at> Iterator for Verifier<'at> {
  type Item = &'at String;
  fn next(&mut self) -> Option<Self::Item> {
    self.0.next()
  }
}

impl <'at> Db for Verifier<'at> {
  fn auth<A : Serialize + DeserializeOwned>(&mut self, a:A) -> Proof<A> {
    Proof { value: None, hash: hash(&a) }
  }
  fn unauth<A : Serialize + DeserializeOwned>(&mut self, p: Proof<A>) -> A {
    let v = self.next().unwrap();
    assert_eq!(p.hash,hash_str(&v));
    serde_json::from_str(&v).unwrap()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde::{Serialize,Deserialize};
  #[derive(Serialize,Deserialize)]
  pub enum Tree {
    Tip(u32),
    Bin(u32,Box<Proof<Tree>>,Box<Proof<Tree>>)
  }

  pub enum Dir {
    L,
    R
  }

  type Path = [Dir];

  fn tip(u: u32) -> Tree { Tree::Tip(u) }
  fn bin<D:Db>(db:&mut D, a: u32, l: Tree, r: Tree) -> Tree {
    let nl = db.auth(l);
    let nr = db.auth(r);
    Tree::Bin(a,Box::new(nl), Box::new(nr))
  }

  fn at<D:Db>(db:&mut D,mut t: Tree, p:&Path) -> Option<u32> {
    for ele in p {
      if let Tree::Bin(_a,l,r) = t {
        let nt = match ele {
          Dir::L => l,
          Dir::R => r
        };
        t = db.unauth(*nt);
      } else {
        None?
      }
    }
    match t {
      Tree::Bin(a,_,_) => Some(a),
      Tree::Tip(a) => Some(a)
    }
  }

  fn go<D:Db>(db:&mut D) -> Option<u32> {
    let y = bin(db,0,tip(1),tip(2));
    let x = bin(db,0,y,tip(2));
    at(db,x,&[Dir::L,Dir::R])
  }

  #[test]
  fn it_works() {
    let mut p = Prover::new();
    let result = go(&mut p);
    println!("{result:?}");

    let mut v = p.verify();
    let result2 = go(&mut v);
    println!("{result2:?}");
    assert_eq!(result,result2)
  }
}
