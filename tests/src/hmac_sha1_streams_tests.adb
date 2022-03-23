pragma Ada_2012;

with AUnit.Assertions; use AUnit.Assertions;
with AUnit.Test_Caller;

with Ada.Streams; use Ada.Streams;
with HMAC;        use HMAC.HMAC_SHA1;

package body HMAC_SHA1_Streams_Tests is
   package Caller is new AUnit.Test_Caller (Fixture);

   Test_Suite : aliased AUnit.Test_Suites.Test_Suite;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
      Name : constant String := "[HMAC_SHA1 - Ada.Streams] ";
   begin
      Test_Suite.Add_Test
        (Caller.Create
           (Name & "HMAC_SHA1() - RFC 2202 test vectors",
            HMAC_SHA1_RFC2202_Test'Access));
      return Test_Suite'Access;
   end Suite;

   procedure HMAC_SHA1_RFC2202_Test (Object : in out Fixture) is
      function HMAC (Key, Message : String) return Stream_Element_Array renames
        HMAC.HMAC_SHA1.HMAC;
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
              (16#b6#, 16#17#, 16#31#, 16#86#, 16#55#, 16#05#, 16#72#, 16#64#,
               16#e2#, 16#8b#, 16#c0#, 16#b6#, 16#fb#, 16#37#, 16#8c#, 16#8e#,
               16#f1#, 16#46#, 16#be#, 16#00#),
            "test case no. 1");
      end;

      Assert
        (HMAC (Key => "Jefe", Message => "what do ya want for nothing?") =
         Stream_Element_Array'
           (16#ef#, 16#fc#, 16#df#, 16#6a#, 16#e5#, 16#eb#, 16#2f#, 16#a2#,
            16#d2#, 16#74#, 16#16#, 16#d5#, 16#f1#, 16#84#, 16#df#, 16#9c#,
            16#25#, 16#9a#, 16#7c#, 16#79#),
         "test case no. 2");

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 20 => 16#aa#));
      begin
         Update (Ctx, Stream_Element_Array'(1 .. 50 => 16#dd#));
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#12#, 16#5d#, 16#73#, 16#42#, 16#b9#, 16#ac#, 16#11#, 16#cd#,
               16#91#, 16#a3#, 16#9a#, 16#f4#, 16#8a#, 16#a1#, 16#7b#, 16#4f#,
               16#63#, 16#f1#, 16#75#, 16#d3#),
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
              (16#4c#, 16#90#, 16#07#, 16#f4#, 16#02#, 16#62#, 16#50#, 16#c6#,
               16#bc#, 16#84#, 16#14#, 16#f9#, 16#bf#, 16#50#, 16#c8#, 16#6c#,
               16#2d#, 16#72#, 16#35#, 16#da#),
            "test case no. 4");
      end;

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 20 => 16#0c#));
      begin
         Update (Ctx, "Test With Truncation");
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#4c#, 16#1a#, 16#03#, 16#42#, 16#4b#, 16#55#, 16#e0#, 16#7f#,
               16#e7#, 16#f2#, 16#7b#, 16#e1#, 16#d5#, 16#8b#, 16#b9#, 16#32#,
               16#4a#, 16#9a#, 16#5a#, 16#04#),
            "test case no. 5");
      end;

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 80 => 16#aa#));
      begin
         Update
           (Ctx, "Test Using Larger Than Block-Size Key - Hash Key First");
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#aa#, 16#4a#, 16#e5#, 16#e1#, 16#52#, 16#72#, 16#d0#, 16#0e#,
               16#95#, 16#70#, 16#56#, 16#37#, 16#ce#, 16#8a#, 16#3b#, 16#55#,
               16#ed#, 16#40#, 16#21#, 16#12#),
            "test case no. 6");
      end;

      declare
         Ctx : Context :=
           Initialize (Stream_Element_Array'(1 .. 80 => 16#aa#));
      begin
         Update
           (Ctx,
            "Test Using Larger Than Block-Size Key and" &
            " Larger Than One Block-Size Data");
         Assert
           (Finalize (Ctx) =
            Stream_Element_Array'
              (16#e8#, 16#e9#, 16#9d#, 16#0f#, 16#45#, 16#23#, 16#7d#, 16#78#,
               16#6d#, 16#6b#, 16#ba#, 16#a7#, 16#96#, 16#5c#, 16#78#, 16#08#,
               16#bb#, 16#ff#, 16#1a#, 16#91#),
            "test case no. 7");
      end;
   end HMAC_SHA1_RFC2202_Test;
end HMAC_SHA1_Streams_Tests;
