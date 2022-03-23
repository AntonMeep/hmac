with Ada.Streams; use Ada.Streams;

with SHA1;

with HMAC_Generic;

package HMAC with
   Pure,
   Preelaborate
is
   package HMAC_SHA1 is new HMAC_Generic
     (Element       => Stream_Element, Index => Stream_Element_Offset,
      Element_Array => Stream_Element_Array,

      Digest_Length => SHA1.Digest_Length, Block_Length => SHA1.Block_Length,

      Hash_Context => SHA1.Context, Hash_Initialize => SHA1.Initialize,
      Hash_Update  => SHA1.Update, Hash_Finalize => SHA1.Finalize);
end HMAC;
