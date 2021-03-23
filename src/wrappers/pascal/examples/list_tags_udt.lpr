program list_tags_udt;

{$mode objfpc}{$H+}
{$modeswitch advancedrecords}

uses
  libplctagv2, ctypes, SysUtils, fgl,
  Classes
  { you can add units after this };

Const
  DefaultTimeout = 10000;
  TAG_STRING_SIZE = 200;

  TYPE_IS_SYSTEM:cuint16 = $1000;
  TYPE_IS_STRUCT:cuint16 = $8000;
  TAG_DIM_MASK:cuint16   = $6000;

type
  { TLGXTagList }

  TLGXProgramList = specialize TFPGList<string>;
  TLGXTag = record
    instance_id:cint32;
    name:String;
    aType,
    elem_size,
    elem_count,
    num_dimensions:cuint16;
    dimensions:array[0..2] of cuint16;
    raw_size:cuint32;
    class operator = (a, b: TLGXTag) r: Boolean;
  end;

  TLGXTagList = specialize TFPGMap<String, TLGXTag>;

  { Tudt_field_entry }

  TUDT_field_entry = record
    name:String;
    aType   :cuint16;
    metadata:cuint16;
    size  :cuint32;
    offset:cuint32;
    class operator = (a, b: Tudt_field_entry) r: Boolean;
  end;
  PUDT_field_entry = ^TUDT_field_entry;

  TUDTFieldList = specialize TFPGList<Pudt_field_entry>;

  { Tudt_entry }

  Tudt_entry = record
  private
    class operator initialize(var aRec:Tudt_entry);
    class operator finalize(var aRec:Tudt_entry);
    class operator Copy(constref aSrc: Tudt_entry; var aDst: Tudt_entry);
  public
    name:String;
    id           :cuint16;
    num_fields   :cuint16;
    struct_handle:cuint16;
    instance_size:cuint32;
    fields:TUDTFieldList;
  end;
  Pudt_entry = ^Tudt_entry;

  TUDTID = 0..$FFF;

  TUDTList = specialize TFPGMap<TUDTID,Pudt_entry>;

var
  FLGXTagList:TLGXTagList;
  FLGXUDTList:TUDTList;

class operator TLGXTag.=(a, b: TLGXTag)r: Boolean;
begin
  result:=
    (a.instance_id    = b.instance_id   ) and
    (a.name           = b.name          ) and
    (a.aType          = b.aType         ) and
    (a.elem_size      = b.elem_size     ) and
    (a.elem_count     = b.elem_count    ) and
    (a.num_dimensions = b.num_dimensions) and
    (a.dimensions[0]  = b.dimensions[0] ) and
    (a.dimensions[1]  = b.dimensions[1] ) and
    (a.dimensions[2]  = b.dimensions[2] ) and
    (a.raw_size       = b.raw_size      );
end;

class operator Tudt_field_entry.=(a, b: Tudt_field_entry)r: Boolean;
begin
  r:=(a.name     = b.name    ) and
     (a.aType    = b.aType   ) and
     (a.metadata = b.metadata) and
     (a.size     = b.size    ) and
     (a.offset   = b.offset  );
end;

class operator Tudt_entry.initialize(var aRec: Tudt_entry);
begin
  aRec.fields:=TUDTFieldList.Create;
end;

class operator Tudt_entry.finalize(var aRec: Tudt_entry);
begin
  if Assigned(aRec.fields) then
    FreeAndNil(aRec.fields);
end;

class operator Tudt_entry.Copy(constref aSrc: Tudt_entry; var aDst: Tudt_entry);
begin
  ADst.name         :=aSrc.name         ;
  ADst.id           :=aSrc.id           ;
  ADst.num_fields   :=aSrc.num_fields   ;
  ADst.struct_handle:=aSrc.struct_handle;
  ADst.instance_size:=aSrc.instance_size;
  aDst.fields.Assign(aSrc.fields);
end;

function BuildLibPLCTagName: String;
begin
  Result:='protocol=ab_eip2&gateway='+ParamStr(1)+'&path='+ParamStr(2)+'&cpu=controllogix&';
end;

procedure LoadLGXTagList;
  function setup_tag(aProgram:String = ''):cint32;
  var
    fullTagName: String = '';
  begin
    Result:=PLCTAG_ERR_CREATE;

    if (Trim(aProgram)='') then
      fullTagName:=BuildLibPLCTagName+'name=@tags'
    else
      fullTagName:=BuildLibPLCTagName+'name='+aProgram+'.@tags';

    Result := plc_tag_create(PChar(fullTagName), DefaultTimeout);
  end;

  function LoadUDTData(aUDT:TUDTID; const StructTagPath:String):Boolean;
  var
    idx, offset, f: Integer;
    tag_entry:TLGXTag;
    aUDTInfoTagPath: String;
    aUDTInfoTag: cint32;
    rc, tag_size, name_len: cint;
    udtidx: LongInt;
    auxrec: Pudt_entry;
    aux: PUDT_field_entry;

    procedure AddToTagList;
    var
      f, mykey: Integer;
    begin
      mykey:=FLGXUDTList.Keys[idx];
      for f:=0 to FLGXUDTList.KeyData[mykey]^.fields.Count-1 do begin
        tag_entry.instance_id := -1;
        tag_entry.name := StructTagPath+'.'+lowercase(FLGXUDTList.KeyData[mykey]^.fields[f]^.name);
        tag_entry.aType := FLGXUDTList.KeyData[mykey]^.fields[f]^.aType;
        tag_entry.elem_size := FLGXUDTList.KeyData[mykey]^.fields[f]^.size;
        tag_entry.num_dimensions := ((tag_entry.aType and TAG_DIM_MASK) shr 13);
        tag_entry.dimensions[0] := 0;//array_dims[0];
        tag_entry.dimensions[1] := 0;//array_dims[1];
        tag_entry.dimensions[2] := 0;//array_dims[2];

        writeln(Format('%4.4x %s',[tag_entry.aType, tag_entry.name]));
        FLGXTagList.Add(tag_entry.name);

        if ((tag_entry.aType and TYPE_IS_STRUCT)=TYPE_IS_STRUCT) and ((tag_entry.aType and TYPE_IS_SYSTEM)<>TYPE_IS_SYSTEM) then
          LoadUDTData(tag_entry.aType and $FFF,tag_entry.name);
      end;
    end;
  begin
    if FLGXUDTList.Find(aUDT, idx) then
      AddToTagList
    else begin
      aUDTInfoTagPath:=BuildLibPLCTagName+'name=@udt/'+IntToStr(aUDT);
      try
        aUDTInfoTag:=plc_tag_create(PChar(aUDTInfoTagPath),DefaultTimeout);
        if aUDTInfoTag>=PLCTAG_STATUS_OK then begin
          rc := plc_tag_read(aUDTInfoTag, DefaultTimeout);
          if rc=PLCTAG_STATUS_OK then begin
            tag_size := plc_tag_get_size(aUDTInfoTag);

            {* the format in the tag buffer is:
             *
             * A new header:
             *
             * uint16_t - UDT ID
             * uint16_t - number of members (including invisible ones)
             * uint16_t - struct handle/CRC of field defs.
             * uint32_t - instance size in bytes.
             *
             * Then the raw field info.
             *
             * N x field info entries
             *     uint16_t field_metadata - array element count or bit field number
             *     uint16_t field_type
             *     uint32_t field_offset
             *
             * int8_t string - zero-terminated string, UDT name, but name stops at first semicolon!
             *
             * N x field names
             *     int8_t string - zero-terminated.
             *
             *}

            New(auxrec);
            udtidx:=FLGXUDTList.Add(aUDT, auxrec);
            FLGXUDTList.Data[udtidx]^.id            := plc_tag_get_uint16(aUDTInfoTag, 0);
            FLGXUDTList.Data[udtidx]^.num_fields    := plc_tag_get_uint16(aUDTInfoTag, 2);
            FLGXUDTList.Data[udtidx]^.struct_handle := plc_tag_get_uint16(aUDTInfoTag, 4);
            FLGXUDTList.Data[udtidx]^.instance_size := plc_tag_get_uint32(aUDTInfoTag, 6);

            // skip past this header. */
            offset := 10;

            // just a sanity check
            if(FLGXUDTList.Data[udtidx]^.id <> aUDT) then begin
              //TODO:
            end;

            // first section is the field type and size info for all fields.
            for f:=0 to FLGXUDTList.Data[udtidx]^.num_fields-1 do begin
              new(aux);
              FillByte(aux^,SizeOf(aux),0);

              aux^.metadata := plc_tag_get_uint16(aUDTInfoTag, offset);
              inc(offset, 2);

              aux^.aType := plc_tag_get_uint16(aUDTInfoTag, offset);
              inc(offset, 2);

              aux^.offset := plc_tag_get_uint32(aUDTInfoTag, offset);
              inc(offset, 4);

              FLGXUDTList.Data[udtidx]^.fields.Add(aux);
            end;

            {*
             * then get the template/UDT name.   This is weird.
             * Scan until we see a 0x3B, semicolon, byte.   That is the end of the
             * template name.   Actually we should look for ";n" but the semicolon
             * seems to be enough for now.
             *}
            // copy the name */
            rc := plc_tag_get_pascal_string(aUDTInfoTag, offset, FLGXUDTList.Data[udtidx]^.name);
            if (rc <> PLCTAG_STATUS_OK) then begin
              //TODO:
            end;

            // skip past the UDT name.
            inc(offset,  plc_tag_get_string_total_length(aUDTInfoTag, offset));

            f:=0;
            while ((f < FLGXUDTList.Data[udtidx]^.num_fields) and (offset < tag_size)) do begin
              aux:=FLGXUDTList.Data[udtidx]^.fields[f];
              rc := plc_tag_get_pascal_string(aUDTInfoTag, offset, FLGXUDTList.Data[udtidx]^.fields[f]^.name);
              if (rc <> PLCTAG_STATUS_OK) then begin
                //TODO?
              end;

              inc(offset,  plc_tag_get_string_total_length(aUDTInfoTag, offset));
              inc(f);
            end;

            // sanity check
            if(offset <> tag_size - 1) then
              Writeln(Format('Processed %d bytes out of %d bytes.',[offset, tag_size]));

            idx:=udtidx;
            AddToTagList;

          end else begin
            //TODO:
            writeln('DEU RUIM 2!');
          end;
        end else begin
          //TODO:
          writeln('DEU RUIM 1!');
        end;
      finally
        plc_tag_destroy(aUDTInfoTag);
      end;
    end;
  end;

  procedure get_list(tag:cint32; prefix:String; tag_list:TLGXTagList; prog_list:TLGXProgramList; AddPrefixToTagNameList:Boolean = true);
  var
    rc:cint = PLCTAG_STATUS_OK;
    offset:cint = 0;

    //repeat vars
    tag_instance_id:cuint32 = 0;
    tag_type:cuint16 = 0;
    element_length:cuint16 = 0;
    array_dims:array[0..2] of cuint16 =(0,0,0);
    tag_name_len:cint = 0;
    tag_namePChar:Pchar = nil;
    tag_name:String;
    tag_entry, tag_entry2:TLGXTag;
    i, d1, d2, d3: Integer;
    a, b: Boolean;
  begin
    rc := plc_tag_read(tag, DefaultTimeout);
    if (rc <> PLCTAG_STATUS_OK) then begin
      writeln('Unable to read tag!  Return code ',tag,' "'+plc_tag_decode_error(tag),'"');
      exit;
    end;

    repeat
      { each entry looks like this:
          uint32_t instance_id    monotonically increasing but not contiguous
          uint16_t symbol_type    type of the symbol.
          uint16_t element_length length of one array element in bytes.
          uint32_t array_dims[3]  array dimensions.
          uint16_t string_len     string length count.
          uint8_t string_data[]   string bytes (string_len of them)
      }

      tag_instance_id := plc_tag_get_uint32(tag, offset);
      inc(offset,4);
      tag_type := plc_tag_get_uint16(tag, offset);
      inc(offset, 2);

      element_length := plc_tag_get_uint16(tag, offset);
      inc(offset, 2);

      array_dims[0] := plc_tag_get_uint32(tag, offset);
      inc(offset, 4);
      array_dims[1] := plc_tag_get_uint32(tag, offset);
      inc(offset, 4);
      array_dims[2] := plc_tag_get_uint32(tag, offset);
      inc(offset, 4);

      // use library support for strings. Offset points to the start of the string.
      tag_name_len := plc_tag_get_string_length(tag, offset) + 1; // add +1 for the zero byte.

      // allocate space for the prefix plus the tag name.
      try
        tag_namePChar := GetMem(tag_name_len);
        if (tag_namePChar=nil) then begin
          writeln('Unable to allocate memory for the tag name!');
          continue;
        end;

        rc := plc_tag_get_string(tag, offset, tag_namePChar, tag_name_len);
        if(rc <> PLCTAG_STATUS_OK) then begin
            WriteLn('Unable to get the tag name string, got error ', plc_tag_decode_error(rc));
            continue;
        end;
        tag_name := tag_namePChar;
      finally
        Freemem(tag_namePChar);
      end;

      inc(offset, plc_tag_get_string_total_length(tag, offset));

      if pos('program:',lowercase(tag_name))>0 then
        prog_list.Add(tag_name)
      else begin
        if ((tag_type and TYPE_IS_SYSTEM)<>TYPE_IS_SYSTEM) then begin

          tag_entry.elem_count := 1;

          // fill in the fields.
          tag_entry.instance_id := tag_instance_id;
          if (trim(prefix)='') or (AddPrefixToTagNameList=false) then
            tag_entry.name := tag_name
          else
            tag_entry.name := prefix+'.'+tag_name;

          tag_entry.aType := tag_type;
          writeln(Format('%4.4x %s',[tag_entry.aType, tag_entry.name]));
          tag_entry.elem_size := element_length;
          tag_entry.num_dimensions := ((tag_type and TAG_DIM_MASK) shr 13);
          tag_entry.dimensions[0] := array_dims[0];
          tag_entry.dimensions[1] := array_dims[1];
          tag_entry.dimensions[2] := array_dims[2];

          for i:=0 to tag_entry.num_dimensions-1 do
            tag_entry.elem_count := tag_entry.elem_count * tag_entry.dimensions[i];

          tag_entry.raw_size:=tag_entry.elem_count*tag_entry.elem_size;

          FLGXTagList.Add(LowerCase(tag_entry.name), tag_entry);
          //writeln(tag_entry.name,' ec=',tag_entry.elem_count,' es=',tag_entry.elem_size);

          //é um array, então adiciona os acessos diretos aos elementos da array.
          if tag_entry.num_dimensions in [1..3] then begin
            tag_entry2:=tag_entry;
            tag_entry2.name           := tag_entry.name;
            tag_entry2.aType          := tag_entry.aType;
            tag_entry2.num_dimensions := 0;
            tag_entry2.dimensions[0]  := 0;
            tag_entry2.dimensions[1]  := 0;
            tag_entry2.dimensions[2]  := 0;
            tag_entry.elem_count      := 1;

            for d1:=0 to tag_entry.dimensions[0]-1 do begin
              if tag_entry.num_dimensions=1 then begin
                tag_entry2.name:=tag_entry.name+'['+inttostr(d1)+']';
                FLGXTagList.Add(LowerCase(tag_entry2.name), tag_entry2);
                //writeln(tag_entry2.name,' ec=',tag_entry2.elem_count,' es=',tag_entry2.elem_size);
                if ((tag_entry2.aType and TYPE_IS_STRUCT)=TYPE_IS_STRUCT) and ((tag_entry2.aType and TYPE_IS_SYSTEM)<>TYPE_IS_SYSTEM) then begin
                  LoadUDTData(tag_entry2.aType AND $FFF, tag_entry2.name);
                end;
              end else begin
                for d2:=0 to tag_entry.dimensions[1]-1 do begin
                  if tag_entry.num_dimensions=2 then begin
                    tag_entry2.name:=tag_entry.name+'['+inttostr(d1)+','+inttostr(d2)+']';
                    FLGXTagList.Add(LowerCase(tag_entry2.name), tag_entry2);
                    //writeln(tag_entry2.name,' ec=',tag_entry2.elem_count,' es=',tag_entry2.elem_size);
                    if ((tag_entry2.aType and TYPE_IS_STRUCT)=TYPE_IS_STRUCT) and ((tag_entry2.aType and TYPE_IS_SYSTEM)<>TYPE_IS_SYSTEM) then begin
                      LoadUDTData(tag_entry2.aType AND $FFF, tag_entry2.name);
                    end;
                  end else begin
                    for d3:=0 to tag_entry.dimensions[1]-1 do begin
                      tag_entry2.name:=tag_entry.name+'['+inttostr(d1)+','+inttostr(d2)+','+inttostr(d3)+']';
                      FLGXTagList.Add(LowerCase(tag_entry2.name), tag_entry2);
                      //writeln(tag_entry2.name,' ec=',tag_entry2.elem_count,' es=',tag_entry2.elem_size);
                      if ((tag_entry2.aType and TYPE_IS_STRUCT)=TYPE_IS_STRUCT) and ((tag_entry2.aType and TYPE_IS_SYSTEM)<>TYPE_IS_SYSTEM) then begin
                        LoadUDTData(tag_entry2.aType AND $FFF, tag_entry2.name);
                      end;
                    end;
                  end;
                end;
              end;
            end;
          end else begin
            a:=((tag_entry.aType and TYPE_IS_STRUCT)=TYPE_IS_STRUCT);
            b:=((tag_entry.aType and TYPE_IS_SYSTEM)<>TYPE_IS_SYSTEM);
            if a and b then
              LoadUDTData(tag_entry.aType AND $FFF, tag_entry.name);
          end;
        end;
      end;

    until (rc <>PLCTAG_STATUS_OK) or (offset >= plc_tag_get_size(tag));

    plc_tag_destroy(tag);
  end;

var
  FLGXPrgList: TLGXProgramList;
  aTag:cint32;
  i: Integer;
begin
  if not Assigned(FLGXTagList) then begin
    FLGXTagList:=TLGXTagList.Create;
    FLGXTagList.Sorted:=true;
  end;

  FLGXTagList.Clear;

  try
    aTag:=setup_tag();
    FLGXPrgList:=TLGXProgramList.Create;

    get_list(aTag, '', FLGXTagList, FLGXPrgList);

    for i:=0 to FLGXPrgList.Count-1 do begin
      aTag:=setup_tag(FLGXPrgList.Items[i]);

      get_list(aTag, FLGXPrgList.Items[i], FLGXTagList, nil);
    end;
  finally
    if Assigned(FLGXPrgList) then FLGXPrgList.Free;
  end;
end;

begin
  if ParamCount<>2 then begin
    writeln(ParamStr(0),' <clp-IPv4> <path>');
    WriteLn();
    writeln('Example:');
    writeln(ParamStr(0),' 192.168.10.177 1,0');
    writeln;
    writeln('This example only works with Compact/ControlLogix PLCs!!');
    Halt(1);
  end;
  plc_tag_set_debug_level(PLCTAG_DEBUG_DETAIL);

  FLGXTagList:=TLGXTagList.Create;
  try
    FLGXTagList.Sorted:=true;
    FLGXUDTList:=TUDTList.Create;
    try
      FLGXUDTList.Sorted:=true;
      LoadLGXTagList;
    finally
      FLGXUDTList.Free;
    end;
  finally
    FLGXTagList.Free;
  end;
end.

