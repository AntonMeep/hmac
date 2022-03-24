with AUnit.Test_Fixtures;
with AUnit.Test_Suites;

package HMAC_SHA2_Streams_Tests is
   function Suite return AUnit.Test_Suites.Access_Test_Suite;
private
   type Fixture is new AUnit.Test_Fixtures.Test_Fixture with null record;

   procedure HMAC_SHA_224_Test (Object : in out Fixture);
   procedure HMAC_SHA_256_Test (Object : in out Fixture);
   procedure HMAC_SHA_384_Test (Object : in out Fixture);
   procedure HMAC_SHA_512_Test (Object : in out Fixture);
end HMAC_SHA2_Streams_Tests;
