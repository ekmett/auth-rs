#![feature(specialization)]

use derivative::{self,Derivative};
use digest::Output;
use hex;
use serde_json;
use serde::ser::{Serialize, Serializer};
use serde::de::{Deserialize, Deserializer, Visitor};
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

pub trait Evidence where
  Self::Of : Serialize,
{
  type Of;
  type Db;
  fn auth(a:Self::Of) -> Self;
  fn unauth(self, db: &mut Self::Db) -> Self::Of;
}

pub trait AuthEvidence
{
  type Of;
  type Db;
  fn authauth(a:Self::Of) -> Self;
  fn unauthauth(self, db: &mut Self::Db) -> Self::Of;
}

impl <T: AuthEvidence> Evidence for T where
  <T as AuthEvidence>::Of : Serialize {
  type Of = <T as AuthEvidence>::Of;
  type Db = <T as AuthEvidence>::Db;

  fn auth(a:Self::Of) -> Self {
    T::authauth(a)
  }
  fn unauth(self, db: &mut Self::Db) -> Self::Of {
    T::unauthauth(self,db)
  }
}

pub trait HasEvidence<A> where 
  Self::Ev : Evidence<Of=A,Db=Self> { 
    type Ev;
}

#[derive(Debug)]
pub struct Prover(Vec<String>);

impl <A: Serialize> HasEvidence<A> for Prover {
  type Ev = Proof<A>;
}

#[derive(Debug,Copy,Clone,Derivative)]
#[derivative(Hash,PartialEq,Eq,PartialOrd,Ord)]
pub struct Proof<A>(
  #[derivative(Hash="ignore",PartialEq="ignore",PartialOrd="ignore")]
  A,
  HashCode
);


impl <A> Display for Proof<A> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    hex::encode(self.1).fmt(f)
  }
}

impl <A> Serialize for Proof<A> {
  fn serialize<S>(&self,s:S) -> Result<S::Ok, S::Error> where
    S: Serializer,
  {
    s.serialize_str(&hex::encode(self.1))
  }
}

impl <A: Serialize> Evidence for Proof<A> 
{
  type Of = A;
  type Db = Prover;
  fn auth(a:A) -> Self {
    let h = hash(&a);
    Proof(a,h)
  }
  fn unauth(self, db: &mut Self::Db) -> A {
    db.0.push(serde_json::to_string(&self.0).unwrap());
    self.0
  }
}

impl <T> AuthEvidence for Proof<Proof<T>> {}


#[derive(Debug,Clone)]
pub struct Verifier<'at>(slice::Iter<'at,String>);

impl <'at> Iterator for Verifier<'at> {
  type Item = &'at String;
  fn next(&mut self) -> Option<Self::Item> {
    self.0.next()
  }
}

#[derive(Debug,Copy,Clone,Derivative)]
#[derivative(Hash,PartialEq,Eq,PartialOrd,Ord)]
pub struct Verified<'at,A>(
  #[derivative(Hash="ignore",PartialEq="ignore",PartialOrd="ignore")]
  PhantomData<&'at A>, 
  HashCode
);

impl <'at,A> Evidence for Verified<'at,A> where
  A: Serialize + Deserialize<'at> + 'at
{
  type Of = A;
  type Db = Verifier<'at>;

  fn auth(a:A) -> Self {
    Verified(PhantomData,hash(&a))
  }

  fn unauth(self, db: &mut Verifier<'at>) -> A {
    let v = db.next().unwrap();
    assert_eq!(self.1,hash_str(&v));
    serde_json::from_str(&v).unwrap()
  }
}

impl <'at,A> HasEvidence<A> for Verifier<'at> where 
  A: Serialize + Deserialize<'at> + 'at 
{
  type Ev = Verified<'at,A>;
}

impl <'at,A> Serialize for Verified<'at,A> {
  fn serialize<S>(&self,s:S) -> Result<S::Ok, S::Error> where
    S: Serializer,
  {
    s.serialize_str(&hex::encode(self.1))
  }
}

struct VerifiedVisitor<'at,A>(PhantomData<&'at A>);

impl<'de,'at, A> Visitor<'de> for VerifiedVisitor<'at,A> {
    type Value = Verified<'at,A>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a hashed structure")
    }

    fn visit_string<E>(self, h: String) -> Result<Self::Value, E> where
      E: serde::de::Error,
    {
      let v = hex::decode(h).unwrap();
      Ok(Verified(PhantomData,HashCode::from(<[u8;20]>::try_from(v).unwrap())))
    }
}

impl <'at,'de,A> Deserialize<'de> for Verified<'at,A> {
  fn deserialize<D>(d:D) -> Result<Self, D::Error> where
    D: Deserializer<'de> {
    d.deserialize_str(VerifiedVisitor(PhantomData))
  }
}


