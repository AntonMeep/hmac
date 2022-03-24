pragma Ada_2012;

with AUnit.Assertions; use AUnit.Assertions;
with AUnit.Test_Caller;

with Ada.Streams; use Ada.Streams;
with HMAC;

package body HMAC_SHA2_Streams_Tests is
   package Caller is new AUnit.Test_Caller (Fixture);

   Test_Suite : aliased AUnit.Test_Suites.Test_Suite;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
      Name : constant String := "[HMAC_SHA2 - Ada.Streams] ";
   begin
      Test_Suite.Add_Test
        (Caller.Create
           (Name & "HMAC_SHA_224() - RFC 4231 test vectors",
            HMAC_SHA_224_Test'Access));
      Test_Suite.Add_Test
        (Caller.Create
           (Name & "HMAC_SHA_256() - RFC 4231 test vectors",
            HMAC_SHA_256_Test'Access));
      Test_Suite.Add_Test
        (Caller.Create
           (Name & "HMAC_SHA_384() - RFC 4231 test vectors",
            HMAC_SHA_384_Test'Access));
      Test_Suite.Add_Test
        (Caller.Create
           (Name & "HMAC_SHA_512() - RFC 4231 test vectors",
            HMAC_SHA_512_Test'Access));

      return Test_Suite'Access;
   end Suite;

   procedure HMAC_SHA_224_Test (Object : in out Fixture) is
      use HMAC.HMAC_SHA_224;
      function HMAC (Key, Message : String) return Stream_Element_Array renames
        HMAC.HMAC_SHA_224.HMAC;
   begin
      declare
         Ctx : Context :=
           Initialize
             (Stream_Element_Array'
                (16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#,
                 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#,
                 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#));
      begin
         Update (Ctx, "Hi There");
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#89#, 16#6f#, 16#b1#, 16#12#, 16#8a#, 16#bb#, 16#df#, 16#19#,
               16#68#, 16#32#, 16#10#, 16#7c#, 16#d4#, 16#9d#, 16#f3#, 16#3f#,
               16#47#, 16#b4#, 16#b1#, 16#16#, 16#99#, 16#12#, 16#ba#, 16#4f#,
               16#53#, 16#68#, 16#4b#, 16#22#),
            "test case no. 1");
      end;

      Assert
        (HMAC (Key => "Jefe", Message => "what do ya want for nothing?") =
         Stream_Element_Array'
           (16#a3#, 16#0e#, 16#01#, 16#09#, 16#8b#, 16#c6#, 16#db#, 16#bf#,
            16#45#, 16#69#, 16#0f#, 16#3a#, 16#7e#, 16#9e#, 16#6d#, 16#0f#,
            16#8b#, 16#be#, 16#a2#, 16#a3#, 16#9e#, 16#61#, 16#48#, 16#00#,
            16#8f#, 16#d0#, 16#5e#, 16#44#),
         "test case no. 2");

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 20 => 16#aa#));
      begin
         Update (Ctx, Stream_Element_Array'(1 .. 50 => 16#dd#));
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#7f#, 16#b3#, 16#cb#, 16#35#, 16#88#, 16#c6#, 16#c1#, 16#f6#,
               16#ff#, 16#a9#, 16#69#, 16#4d#, 16#7d#, 16#6a#, 16#d2#, 16#64#,
               16#93#, 16#65#, 16#b0#, 16#c1#, 16#f6#, 16#5d#, 16#69#, 16#d1#,
               16#ec#, 16#83#, 16#33#, 16#ea#),
            "test case no. 3");
      end;

      declare
         Ctx : Context :=
           Initialize
             (Stream_Element_Array'
                (16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
                 16#08#, 16#09#, 16#0a#, 16#0b#, 16#0c#, 16#0d#, 16#0e#,
                 16#0f#, 16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#,
                 16#16#, 16#17#, 16#18#, 16#19#));
      begin
         Update (Ctx, Stream_Element_Array'(1 .. 50 => 16#cd#));
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#6c#, 16#11#, 16#50#, 16#68#, 16#74#, 16#01#, 16#3c#, 16#ac#,
               16#6a#, 16#2a#, 16#bc#, 16#1b#, 16#b3#, 16#82#, 16#62#, 16#7c#,
               16#ec#, 16#6a#, 16#90#, 16#d8#, 16#6e#, 16#fc#, 16#01#, 16#2d#,
               16#e7#, 16#af#, 16#ec#, 16#5a#),
            "test case no. 4");
      end;

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 20 => 16#0c#));
      begin
         Update (Ctx, "Test With Truncation");
         Assert
           (Finalize (Ctx) (0 .. 15) =
            Stream_Element_Array'
              (16#0e#, 16#2a#, 16#ea#, 16#68#, 16#a9#, 16#0c#, 16#8d#, 16#37#,
               16#c9#, 16#88#, 16#bc#, 16#db#, 16#9f#, 16#ca#, 16#6f#, 16#a8#),
            "test case no. 5");
      end;

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 131 => 16#aa#));
      begin
         Update
           (Ctx, "Test Using Larger Than Block-Size Key - Hash Key First");
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#95#, 16#e9#, 16#a0#, 16#db#, 16#96#, 16#20#, 16#95#, 16#ad#,
               16#ae#, 16#be#, 16#9b#, 16#2d#, 16#6f#, 16#0d#, 16#bc#, 16#e2#,
               16#d4#, 16#99#, 16#f1#, 16#12#, 16#f2#, 16#d2#, 16#b7#, 16#27#,
               16#3f#, 16#a6#, 16#87#, 16#0e#),
            "test case no. 6");
      end;

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 131 => 16#aa#));
      begin
         Update
           (Ctx,
            "This is a test u" & "sing a larger th" & "an block-size ke" &
            "y and a larger t" & "han block-size d" & "ata. The key nee" &
            "ds to be hashed " & "before being use" & "d by the HMAC al" &
            "gorithm.");
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#3a#, 16#85#, 16#41#, 16#66#, 16#ac#, 16#5d#, 16#9f#, 16#02#,
               16#3f#, 16#54#, 16#d5#, 16#17#, 16#d0#, 16#b3#, 16#9d#, 16#bd#,
               16#94#, 16#67#, 16#70#, 16#db#, 16#9c#, 16#2b#, 16#95#, 16#c9#,
               16#f6#, 16#f5#, 16#65#, 16#d1#),
            "test case no. 7");
      end;
   end HMAC_SHA_224_Test;

   procedure HMAC_SHA_256_Test (Object : in out Fixture) is
      use HMAC.HMAC_SHA_256;
      function HMAC (Key, Message : String) return Stream_Element_Array renames
        HMAC.HMAC_SHA_256.HMAC;
   begin
      declare
         Ctx : Context :=
           Initialize
             (Stream_Element_Array'
                (16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#,
                 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#,
                 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#));
      begin
         Update (Ctx, "Hi There");
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#b0#, 16#34#, 16#4c#, 16#61#, 16#d8#, 16#db#, 16#38#, 16#53#,
               16#5c#, 16#a8#, 16#af#, 16#ce#, 16#af#, 16#0b#, 16#f1#, 16#2b#,
               16#88#, 16#1d#, 16#c2#, 16#00#, 16#c9#, 16#83#, 16#3d#, 16#a7#,
               16#26#, 16#e9#, 16#37#, 16#6c#, 16#2e#, 16#32#, 16#cf#, 16#f7#),
            "test case no. 1");
      end;

      Assert
        (HMAC (Key => "Jefe", Message => "what do ya want for nothing?") =
         Stream_Element_Array'
           (16#5b#, 16#dc#, 16#c1#, 16#46#, 16#bf#, 16#60#, 16#75#, 16#4e#,
            16#6a#, 16#04#, 16#24#, 16#26#, 16#08#, 16#95#, 16#75#, 16#c7#,
            16#5a#, 16#00#, 16#3f#, 16#08#, 16#9d#, 16#27#, 16#39#, 16#83#,
            16#9d#, 16#ec#, 16#58#, 16#b9#, 16#64#, 16#ec#, 16#38#, 16#43#),
         "test case no. 2");

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 20 => 16#aa#));
      begin
         Update (Ctx, Stream_Element_Array'(1 .. 50 => 16#dd#));
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#77#, 16#3e#, 16#a9#, 16#1e#, 16#36#, 16#80#, 16#0e#, 16#46#,
               16#85#, 16#4d#, 16#b8#, 16#eb#, 16#d0#, 16#91#, 16#81#, 16#a7#,
               16#29#, 16#59#, 16#09#, 16#8b#, 16#3e#, 16#f8#, 16#c1#, 16#22#,
               16#d9#, 16#63#, 16#55#, 16#14#, 16#ce#, 16#d5#, 16#65#, 16#fe#),
            "test case no. 3");
      end;

      declare
         Ctx : Context :=
           Initialize
             (Stream_Element_Array'
                (16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
                 16#08#, 16#09#, 16#0a#, 16#0b#, 16#0c#, 16#0d#, 16#0e#,
                 16#0f#, 16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#,
                 16#16#, 16#17#, 16#18#, 16#19#));
      begin
         Update (Ctx, Stream_Element_Array'(1 .. 50 => 16#cd#));
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#82#, 16#55#, 16#8a#, 16#38#, 16#9a#, 16#44#, 16#3c#, 16#0e#,
               16#a4#, 16#cc#, 16#81#, 16#98#, 16#99#, 16#f2#, 16#08#, 16#3a#,
               16#85#, 16#f0#, 16#fa#, 16#a3#, 16#e5#, 16#78#, 16#f8#, 16#07#,
               16#7a#, 16#2e#, 16#3f#, 16#f4#, 16#67#, 16#29#, 16#66#, 16#5b#),
            "test case no. 4");
      end;

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 20 => 16#0c#));
      begin
         Update (Ctx, "Test With Truncation");
         Assert
           (Finalize (Ctx) (0 .. 15) =
            Stream_Element_Array'
              (16#a3#, 16#b6#, 16#16#, 16#74#, 16#73#, 16#10#, 16#0e#, 16#e0#,
               16#6e#, 16#0c#, 16#79#, 16#6c#, 16#29#, 16#55#, 16#55#, 16#2b#),
            "test case no. 5");
      end;

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 131 => 16#aa#));
      begin
         Update
           (Ctx, "Test Using Larger Than Block-Size Key - Hash Key First");
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#60#, 16#e4#, 16#31#, 16#59#, 16#1e#, 16#e0#, 16#b6#, 16#7f#,
               16#0d#, 16#8a#, 16#26#, 16#aa#, 16#cb#, 16#f5#, 16#b7#, 16#7f#,
               16#8e#, 16#0b#, 16#c6#, 16#21#, 16#37#, 16#28#, 16#c5#, 16#14#,
               16#05#, 16#46#, 16#04#, 16#0f#, 16#0e#, 16#e3#, 16#7f#, 16#54#),
            "test case no. 6");
      end;

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 131 => 16#aa#));
      begin
         Update
           (Ctx,
            "This is a test u" & "sing a larger th" & "an block-size ke" &
            "y and a larger t" & "han block-size d" & "ata. The key nee" &
            "ds to be hashed " & "before being use" & "d by the HMAC al" &
            "gorithm.");
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#9b#, 16#09#, 16#ff#, 16#a7#, 16#1b#, 16#94#, 16#2f#, 16#cb#,
               16#27#, 16#63#, 16#5f#, 16#bc#, 16#d5#, 16#b0#, 16#e9#, 16#44#,
               16#bf#, 16#dc#, 16#63#, 16#64#, 16#4f#, 16#07#, 16#13#, 16#93#,
               16#8a#, 16#7f#, 16#51#, 16#53#, 16#5c#, 16#3a#, 16#35#, 16#e2#),
            "test case no. 7");
      end;
   end HMAC_SHA_256_Test;

   procedure HMAC_SHA_384_Test (Object : in out Fixture) is
      use HMAC.HMAC_SHA_384;
      function HMAC (Key, Message : String) return Stream_Element_Array renames
        HMAC.HMAC_SHA_384.HMAC;
   begin
      declare
         Ctx : Context :=
           Initialize
             (Stream_Element_Array'
                (16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#,
                 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#,
                 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#));
      begin
         Update (Ctx, "Hi There");
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#af#, 16#d0#, 16#39#, 16#44#, 16#d8#, 16#48#, 16#95#, 16#62#,
               16#6b#, 16#08#, 16#25#, 16#f4#, 16#ab#, 16#46#, 16#90#, 16#7f#,
               16#15#, 16#f9#, 16#da#, 16#db#, 16#e4#, 16#10#, 16#1e#, 16#c6#,
               16#82#, 16#aa#, 16#03#, 16#4c#, 16#7c#, 16#eb#, 16#c5#, 16#9c#,
               16#fa#, 16#ea#, 16#9e#, 16#a9#, 16#07#, 16#6e#, 16#de#, 16#7f#,
               16#4a#, 16#f1#, 16#52#, 16#e8#, 16#b2#, 16#fa#, 16#9c#, 16#b6#),
            "test case no. 1");
      end;

      Assert
        (HMAC (Key => "Jefe", Message => "what do ya want for nothing?") =
         Stream_Element_Array'
           (16#af#, 16#45#, 16#d2#, 16#e3#, 16#76#, 16#48#, 16#40#, 16#31#,
            16#61#, 16#7f#, 16#78#, 16#d2#, 16#b5#, 16#8a#, 16#6b#, 16#1b#,
            16#9c#, 16#7e#, 16#f4#, 16#64#, 16#f5#, 16#a0#, 16#1b#, 16#47#,
            16#e4#, 16#2e#, 16#c3#, 16#73#, 16#63#, 16#22#, 16#44#, 16#5e#,
            16#8e#, 16#22#, 16#40#, 16#ca#, 16#5e#, 16#69#, 16#e2#, 16#c7#,
            16#8b#, 16#32#, 16#39#, 16#ec#, 16#fa#, 16#b2#, 16#16#, 16#49#),
         "test case no. 2");

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 20 => 16#aa#));
      begin
         Update (Ctx, Stream_Element_Array'(1 .. 50 => 16#dd#));
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#88#, 16#06#, 16#26#, 16#08#, 16#d3#, 16#e6#, 16#ad#, 16#8a#,
               16#0a#, 16#a2#, 16#ac#, 16#e0#, 16#14#, 16#c8#, 16#a8#, 16#6f#,
               16#0a#, 16#a6#, 16#35#, 16#d9#, 16#47#, 16#ac#, 16#9f#, 16#eb#,
               16#e8#, 16#3e#, 16#f4#, 16#e5#, 16#59#, 16#66#, 16#14#, 16#4b#,
               16#2a#, 16#5a#, 16#b3#, 16#9d#, 16#c1#, 16#38#, 16#14#, 16#b9#,
               16#4e#, 16#3a#, 16#b6#, 16#e1#, 16#01#, 16#a3#, 16#4f#, 16#27#),
            "test case no. 3");
      end;

      declare
         Ctx : Context :=
           Initialize
             (Stream_Element_Array'
                (16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
                 16#08#, 16#09#, 16#0a#, 16#0b#, 16#0c#, 16#0d#, 16#0e#,
                 16#0f#, 16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#,
                 16#16#, 16#17#, 16#18#, 16#19#));
      begin
         Update (Ctx, Stream_Element_Array'(1 .. 50 => 16#cd#));
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#3e#, 16#8a#, 16#69#, 16#b7#, 16#78#, 16#3c#, 16#25#, 16#85#,
               16#19#, 16#33#, 16#ab#, 16#62#, 16#90#, 16#af#, 16#6c#, 16#a7#,
               16#7a#, 16#99#, 16#81#, 16#48#, 16#08#, 16#50#, 16#00#, 16#9c#,
               16#c5#, 16#57#, 16#7c#, 16#6e#, 16#1f#, 16#57#, 16#3b#, 16#4e#,
               16#68#, 16#01#, 16#dd#, 16#23#, 16#c4#, 16#a7#, 16#d6#, 16#79#,
               16#cc#, 16#f8#, 16#a3#, 16#86#, 16#c6#, 16#74#, 16#cf#, 16#fb#),
            "test case no. 4");
      end;

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 20 => 16#0c#));
      begin
         Update (Ctx, "Test With Truncation");
         Assert
           (Finalize (Ctx) (0 .. 15) =
            Stream_Element_Array'
              (16#3a#, 16#bf#, 16#34#, 16#c3#, 16#50#, 16#3b#, 16#2a#, 16#23#,
               16#a4#, 16#6e#, 16#fc#, 16#61#, 16#9b#, 16#ae#, 16#f8#, 16#97#),
            "test case no. 5");
      end;

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 131 => 16#aa#));
      begin
         Update
           (Ctx, "Test Using Larger Than Block-Size Key - Hash Key First");
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#4e#, 16#ce#, 16#08#, 16#44#, 16#85#, 16#81#, 16#3e#, 16#90#,
               16#88#, 16#d2#, 16#c6#, 16#3a#, 16#04#, 16#1b#, 16#c5#, 16#b4#,
               16#4f#, 16#9e#, 16#f1#, 16#01#, 16#2a#, 16#2b#, 16#58#, 16#8f#,
               16#3c#, 16#d1#, 16#1f#, 16#05#, 16#03#, 16#3a#, 16#c4#, 16#c6#,
               16#0c#, 16#2e#, 16#f6#, 16#ab#, 16#40#, 16#30#, 16#fe#, 16#82#,
               16#96#, 16#24#, 16#8d#, 16#f1#, 16#63#, 16#f4#, 16#49#, 16#52#),
            "test case no. 6");
      end;

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 131 => 16#aa#));
      begin
         Update
           (Ctx,
            "This is a test u" & "sing a larger th" & "an block-size ke" &
            "y and a larger t" & "han block-size d" & "ata. The key nee" &
            "ds to be hashed " & "before being use" & "d by the HMAC al" &
            "gorithm.");
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#66#, 16#17#, 16#17#, 16#8e#, 16#94#, 16#1f#, 16#02#, 16#0d#,
               16#35#, 16#1e#, 16#2f#, 16#25#, 16#4e#, 16#8f#, 16#d3#, 16#2c#,
               16#60#, 16#24#, 16#20#, 16#fe#, 16#b0#, 16#b8#, 16#fb#, 16#9a#,
               16#dc#, 16#ce#, 16#bb#, 16#82#, 16#46#, 16#1e#, 16#99#, 16#c5#,
               16#a6#, 16#78#, 16#cc#, 16#31#, 16#e7#, 16#99#, 16#17#, 16#6d#,
               16#38#, 16#60#, 16#e6#, 16#11#, 16#0c#, 16#46#, 16#52#, 16#3e#),
            "test case no. 7");
      end;
   end HMAC_SHA_384_Test;

   procedure HMAC_SHA_512_Test (Object : in out Fixture) is
      use HMAC.HMAC_SHA_512;
      function HMAC (Key, Message : String) return Stream_Element_Array renames
        HMAC.HMAC_SHA_512.HMAC;
   begin
      declare
         Ctx : Context :=
           Initialize
             (Stream_Element_Array'
                (16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#,
                 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#,
                 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#, 16#0b#));
      begin
         Update (Ctx, "Hi There");
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#87#, 16#aa#, 16#7c#, 16#de#, 16#a5#, 16#ef#, 16#61#, 16#9d#,
               16#4f#, 16#f0#, 16#b4#, 16#24#, 16#1a#, 16#1d#, 16#6c#, 16#b0#,
               16#23#, 16#79#, 16#f4#, 16#e2#, 16#ce#, 16#4e#, 16#c2#, 16#78#,
               16#7a#, 16#d0#, 16#b3#, 16#05#, 16#45#, 16#e1#, 16#7c#, 16#de#,
               16#da#, 16#a8#, 16#33#, 16#b7#, 16#d6#, 16#b8#, 16#a7#, 16#02#,
               16#03#, 16#8b#, 16#27#, 16#4e#, 16#ae#, 16#a3#, 16#f4#, 16#e4#,
               16#be#, 16#9d#, 16#91#, 16#4e#, 16#eb#, 16#61#, 16#f1#, 16#70#,
               16#2e#, 16#69#, 16#6c#, 16#20#, 16#3a#, 16#12#, 16#68#, 16#54#),
            "test case no. 1");
      end;

      Assert
        (HMAC (Key => "Jefe", Message => "what do ya want for nothing?") =
         Stream_Element_Array'
           (16#16#, 16#4b#, 16#7a#, 16#7b#, 16#fc#, 16#f8#, 16#19#, 16#e2#,
            16#e3#, 16#95#, 16#fb#, 16#e7#, 16#3b#, 16#56#, 16#e0#, 16#a3#,
            16#87#, 16#bd#, 16#64#, 16#22#, 16#2e#, 16#83#, 16#1f#, 16#d6#,
            16#10#, 16#27#, 16#0c#, 16#d7#, 16#ea#, 16#25#, 16#05#, 16#54#,
            16#97#, 16#58#, 16#bf#, 16#75#, 16#c0#, 16#5a#, 16#99#, 16#4a#,
            16#6d#, 16#03#, 16#4f#, 16#65#, 16#f8#, 16#f0#, 16#e6#, 16#fd#,
            16#ca#, 16#ea#, 16#b1#, 16#a3#, 16#4d#, 16#4a#, 16#6b#, 16#4b#,
            16#63#, 16#6e#, 16#07#, 16#0a#, 16#38#, 16#bc#, 16#e7#, 16#37#),
         "test case no. 2");

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 20 => 16#aa#));
      begin
         Update (Ctx, Stream_Element_Array'(1 .. 50 => 16#dd#));
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#fa#, 16#73#, 16#b0#, 16#08#, 16#9d#, 16#56#, 16#a2#, 16#84#,
               16#ef#, 16#b0#, 16#f0#, 16#75#, 16#6c#, 16#89#, 16#0b#, 16#e9#,
               16#b1#, 16#b5#, 16#db#, 16#dd#, 16#8e#, 16#e8#, 16#1a#, 16#36#,
               16#55#, 16#f8#, 16#3e#, 16#33#, 16#b2#, 16#27#, 16#9d#, 16#39#,
               16#bf#, 16#3e#, 16#84#, 16#82#, 16#79#, 16#a7#, 16#22#, 16#c8#,
               16#06#, 16#b4#, 16#85#, 16#a4#, 16#7e#, 16#67#, 16#c8#, 16#07#,
               16#b9#, 16#46#, 16#a3#, 16#37#, 16#be#, 16#e8#, 16#94#, 16#26#,
               16#74#, 16#27#, 16#88#, 16#59#, 16#e1#, 16#32#, 16#92#, 16#fb#),
            "test case no. 3");
      end;

      declare
         Ctx : Context :=
           Initialize
             (Stream_Element_Array'
                (16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
                 16#08#, 16#09#, 16#0a#, 16#0b#, 16#0c#, 16#0d#, 16#0e#,
                 16#0f#, 16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#,
                 16#16#, 16#17#, 16#18#, 16#19#));
      begin
         Update (Ctx, Stream_Element_Array'(1 .. 50 => 16#cd#));
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#b0#, 16#ba#, 16#46#, 16#56#, 16#37#, 16#45#, 16#8c#, 16#69#,
               16#90#, 16#e5#, 16#a8#, 16#c5#, 16#f6#, 16#1d#, 16#4a#, 16#f7#,
               16#e5#, 16#76#, 16#d9#, 16#7f#, 16#f9#, 16#4b#, 16#87#, 16#2d#,
               16#e7#, 16#6f#, 16#80#, 16#50#, 16#36#, 16#1e#, 16#e3#, 16#db#,
               16#a9#, 16#1c#, 16#a5#, 16#c1#, 16#1a#, 16#a2#, 16#5e#, 16#b4#,
               16#d6#, 16#79#, 16#27#, 16#5c#, 16#c5#, 16#78#, 16#80#, 16#63#,
               16#a5#, 16#f1#, 16#97#, 16#41#, 16#12#, 16#0c#, 16#4f#, 16#2d#,
               16#e2#, 16#ad#, 16#eb#, 16#eb#, 16#10#, 16#a2#, 16#98#, 16#dd#),
            "test case no. 4");
      end;

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 20 => 16#0c#));
      begin
         Update (Ctx, "Test With Truncation");
         Assert
           (Finalize (Ctx) (0 .. 15) =
            Stream_Element_Array'
              (16#41#, 16#5f#, 16#ad#, 16#62#, 16#71#, 16#58#, 16#0a#, 16#53#,
               16#1d#, 16#41#, 16#79#, 16#bc#, 16#89#, 16#1d#, 16#87#, 16#a6#),
            "test case no. 5");
      end;

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 131 => 16#aa#));
      begin
         Update
           (Ctx, "Test Using Larger Than Block-Size Key - Hash Key First");
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#80#, 16#b2#, 16#42#, 16#63#, 16#c7#, 16#c1#, 16#a3#, 16#eb#,
               16#b7#, 16#14#, 16#93#, 16#c1#, 16#dd#, 16#7b#, 16#e8#, 16#b4#,
               16#9b#, 16#46#, 16#d1#, 16#f4#, 16#1b#, 16#4a#, 16#ee#, 16#c1#,
               16#12#, 16#1b#, 16#01#, 16#37#, 16#83#, 16#f8#, 16#f3#, 16#52#,
               16#6b#, 16#56#, 16#d0#, 16#37#, 16#e0#, 16#5f#, 16#25#, 16#98#,
               16#bd#, 16#0f#, 16#d2#, 16#21#, 16#5d#, 16#6a#, 16#1e#, 16#52#,
               16#95#, 16#e6#, 16#4f#, 16#73#, 16#f6#, 16#3f#, 16#0a#, 16#ec#,
               16#8b#, 16#91#, 16#5a#, 16#98#, 16#5d#, 16#78#, 16#65#, 16#98#),
            "test case no. 6");
      end;

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 131 => 16#aa#));
      begin
         Update
           (Ctx,
            "This is a test u" & "sing a larger th" & "an block-size ke" &
            "y and a larger t" & "han block-size d" & "ata. The key nee" &
            "ds to be hashed " & "before being use" & "d by the HMAC al" &
            "gorithm.");
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#e3#, 16#7b#, 16#6a#, 16#77#, 16#5d#, 16#c8#, 16#7d#, 16#ba#,
               16#a4#, 16#df#, 16#a9#, 16#f9#, 16#6e#, 16#5e#, 16#3f#, 16#fd#,
               16#de#, 16#bd#, 16#71#, 16#f8#, 16#86#, 16#72#, 16#89#, 16#86#,
               16#5d#, 16#f5#, 16#a3#, 16#2d#, 16#20#, 16#cd#, 16#c9#, 16#44#,
               16#b6#, 16#02#, 16#2c#, 16#ac#, 16#3c#, 16#49#, 16#82#, 16#b1#,
               16#0d#, 16#5e#, 16#eb#, 16#55#, 16#c3#, 16#e4#, 16#de#, 16#15#,
               16#13#, 16#46#, 16#76#, 16#fb#, 16#6d#, 16#e0#, 16#44#, 16#60#,
               16#65#, 16#c9#, 16#74#, 16#40#, 16#fa#, 16#8c#, 16#6a#, 16#58#),
            "test case no. 7");
      end;
   end HMAC_SHA_512_Test;
end HMAC_SHA2_Streams_Tests;
