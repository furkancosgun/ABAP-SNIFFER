*&---------------------------------------------------------------------*
*& Report zabap_p_sniffer
*&---------------------------------------------------------------------*
*&
*&---------------------------------------------------------------------*
REPORT zabap_p_sniffer.
TABLES:trdir,tadir,seoclasstx,tlibt,tfdir.

DATA _pattern TYPE text255.

SELECTION-SCREEN BEGIN OF BLOCK b1 WITH FRAME TITLE t01.
SELECT-OPTIONS s_patern FOR _pattern OBLIGATORY NO INTERVALS.
PARAMETERS p_asregx AS CHECKBOX.
SELECTION-SCREEN END OF BLOCK b1.
SELECTION-SCREEN BEGIN OF BLOCK b2 WITH FRAME TITLE t02.
SELECT-OPTIONS s_repnam FOR trdir-name.
SELECT-OPTIONS s_reptyp FOR trdir-subc.
SELECTION-SCREEN END OF BLOCK b2.
SELECTION-SCREEN BEGIN OF BLOCK b3 WITH FRAME TITLE t03.
SELECT-OPTIONS s_packag FOR tadir-devclass.
SELECTION-SCREEN END OF BLOCK b3.
SELECTION-SCREEN BEGIN OF BLOCK b4 WITH FRAME TITLE t04.
SELECT-OPTIONS s_funcnm FOR tfdir-funcname.
SELECT-OPTIONS s_funcgr FOR tlibt-area.
SELECTION-SCREEN END OF BLOCK b4.
SELECTION-SCREEN BEGIN OF BLOCK b5 WITH FRAME TITLE t05.
SELECT-OPTIONS s_clsnam FOR seoclasstx-clsname.
SELECT-OPTIONS s_intfac FOR seoclasstx-clsname.
SELECTION-SCREEN END OF BLOCK b5.
SELECTION-SCREEN BEGIN OF BLOCK b6 WITH FRAME TITLE t06.
SELECT-OPTIONS s_enhanc FOR trdir-name.
PARAMETERS p_withmd AS CHECKBOX.
SELECTION-SCREEN END OF BLOCK b6.

CLASS lcl_sniffer DEFINITION.
  PUBLIC SECTION.
    TYPES ty_source_names  TYPE STANDARD TABLE OF tadir-obj_name WITH EMPTY KEY.
    TYPES ty_range_repname TYPE RANGE OF trdir-name.
    TYPES ty_range_reptype TYPE RANGE OF trdir-subc.
    TYPES ty_range_package TYPE RANGE OF tadir-devclass.
    TYPES ty_range_funcnam TYPE RANGE OF tfdir-funcname.
    TYPES ty_range_funcgrp TYPE RANGE OF tlibt-area.
    TYPES ty_range_clsname TYPE RANGE OF seoclasstx-clsname.
    TYPES ty_range_intface TYPE RANGE OF seoclasstx-clsname.
    TYPES ty_range_enhance TYPE RANGE OF trdir-name.

    TYPES: BEGIN OF ty_sniff_result,
             repname TYPE trdir-name,
             lineidx TYPE n LENGTH 6,
             linesrc TYPE text255,
           END OF ty_sniff_result.

    TYPES ty_sniff_results TYPE TABLE OF ty_sniff_result WITH EMPTY KEY.
    TYPES ty_pattern       TYPE text255.
    TYPES ty_pattern_tab   TYPE TABLE OF ty_pattern WITH EMPTY KEY.

    CLASS-METHODS get_instance
      RETURNING VALUE(ro_instance) TYPE REF TO lcl_sniffer.

    METHODS sniff
      IMPORTING !pattern         TYPE ty_pattern_tab
                isregex          TYPE abap_bool        OPTIONAL
                repname          TYPE ty_range_repname OPTIONAL
                reptype          TYPE ty_range_reptype OPTIONAL
                !package         TYPE ty_range_package OPTIONAL
                funcgrp          TYPE ty_range_funcgrp OPTIONAL
                funcnam          TYPE ty_range_funcnam OPTIONAL
                clsname          TYPE ty_range_clsname OPTIONAL
                intface          TYPE ty_range_intface OPTIONAL
                enhance          TYPE ty_range_enhance OPTIONAL
                withmod          TYPE abap_bool        OPTIONAL
                !comment         TYPE abap_bool        OPTIONAL
      RETURNING VALUE(rt_result) TYPE ty_sniff_results.

  PRIVATE SECTION.
    METHODS get_source_names
      IMPORTING repname                TYPE ty_range_repname
                reptype                TYPE ty_range_reptype
                !package               TYPE ty_range_package
                funcgrp                TYPE ty_range_funcgrp
                funcnam                TYPE ty_range_funcnam
                clsname                TYPE ty_range_clsname
                intface                TYPE ty_range_intface
                enhance                TYPE ty_range_enhance
                withmod                TYPE abap_bool
      RETURNING VALUE(rt_source_names) TYPE ty_source_names.

    METHODS search_sources
      IMPORTING !pattern         TYPE clike
                isregex          TYPE abap_bool
                sources          TYPE ty_source_names
                !comment         TYPE abap_bool
      RETURNING VALUE(rt_result) TYPE ty_sniff_results.

    METHODS add_to_hit_list
      IMPORTING repname   TYPE trdir-name
                repsource TYPE abaptxt255_tab
                matchres  TYPE match_result
                !comment  TYPE abap_bool
      CHANGING  ct_result TYPE ty_sniff_results.

    METHODS get_program_names
      IMPORTING repname                TYPE ty_range_repname
                reptype                TYPE ty_range_reptype
      RETURNING VALUE(rt_source_names) TYPE ty_source_names.

    METHODS get_report_names
      IMPORTING !package               TYPE ty_range_package
      RETURNING VALUE(rt_source_names) TYPE ty_source_names.

    METHODS get_function_names
      IMPORTING funcnam                TYPE ty_range_funcnam
                !package               TYPE ty_range_package
      RETURNING VALUE(rt_source_names) TYPE ty_source_names.

    METHODS get_function_group_names
      IMPORTING funcgrp                TYPE ty_range_funcgrp
                !package               TYPE ty_range_package
      RETURNING VALUE(rt_source_names) TYPE ty_source_names.

    METHODS get_class_names
      IMPORTING clsname                TYPE ty_range_clsname
                !package               TYPE ty_range_package
      RETURNING VALUE(rt_source_names) TYPE ty_source_names.

    METHODS get_interface_names
      IMPORTING intface                TYPE ty_range_intface
                !package               TYPE ty_range_package
      RETURNING VALUE(rt_source_names) TYPE ty_source_names.

    METHODS get_enhancement_names
      IMPORTING enhance                TYPE ty_range_enhance
                !package               TYPE ty_range_package
      RETURNING VALUE(rt_source_names) TYPE ty_source_names.

    METHODS get_modification_names
      IMPORTING withmod                TYPE abap_bool
      RETURNING VALUE(rt_source_names) TYPE ty_source_names.

    METHODS get_class_includes
      IMPORTING clsname            TYPE seoclsname
      RETURNING VALUE(rt_includes) TYPE seoincl_t.

    METHODS get_method_include
      IMPORTING clsname           TYPE seoclsname
                cpdname           TYPE seocpdname
      RETURNING VALUE(rv_include) TYPE progname.

    METHODS get_function_include
      IMPORTING funcname          TYPE funcname
      RETURNING VALUE(rv_include) TYPE progname.

    METHODS get_funcgroup_program
      IMPORTING funcgroup         TYPE tlibt-area
      RETURNING VALUE(rv_program) TYPE progname.

    METHODS get_includes
      CHANGING ct_source_names TYPE ty_source_names.

    METHODS show_progress_bar
      IMPORTING percent TYPE i
                content TYPE clike.

    CLASS-DATA instance TYPE REF TO lcl_sniffer.
ENDCLASS.


CLASS lcl_sniffer IMPLEMENTATION.
  METHOD get_instance.
    IF instance IS NOT BOUND.
      instance = NEW #( ).
    ENDIF.
    ro_instance = instance.
  ENDMETHOD.

  METHOD sniff.
    DATA lt_source_names TYPE ty_source_names.
    DATA lv_pattern      TYPE ty_pattern.

    lt_source_names = get_source_names( repname = repname
                                        reptype = reptype
                                        package = package
                                        funcgrp = funcgrp
                                        funcnam = funcnam
                                        clsname = clsname
                                        intface = intface
                                        enhance = enhance
                                        withmod = withmod ).

    LOOP AT pattern INTO lv_pattern.
      APPEND LINES OF search_sources( pattern = lv_pattern
                                      isregex = isregex
                                      sources = lt_source_names
                                      comment = comment ) TO rt_result.
    ENDLOOP.
  ENDMETHOD.

  METHOD get_source_names.
    APPEND LINES OF me->get_program_names( repname = repname
                                           reptype = reptype )
           TO rt_source_names.

    APPEND LINES OF me->get_report_names( package = package )
           TO rt_source_names.

    APPEND LINES OF me->get_class_names( clsname = clsname
                                         package = package )
           TO rt_source_names.

    APPEND LINES OF me->get_interface_names( intface = intface
                                             package = package )
           TO rt_source_names.

    APPEND LINES OF me->get_function_names( funcnam = funcnam
                                            package = package )
           TO rt_source_names.

    APPEND LINES OF me->get_function_group_names( funcgrp = funcgrp
                                                  package = package )
           TO rt_source_names.

    APPEND LINES OF me->get_enhancement_names( enhance = enhance
                                               package = package )
           TO rt_source_names.

    APPEND LINES OF me->get_modification_names( withmod = withmod )
           TO rt_source_names.

    IF rt_source_names IS INITIAL.
      RETURN.
    ENDIF.

    get_includes( CHANGING ct_source_names = rt_source_names ).

    SORT rt_source_names STABLE BY table_line ASCENDING.
    DELETE ADJACENT DUPLICATES FROM rt_source_names COMPARING table_line.
  ENDMETHOD.

  METHOD show_progress_bar.
    CALL FUNCTION 'SAPGUI_PROGRESS_INDICATOR'
      EXPORTING
        percentage = percent
        text       = content.
  ENDMETHOD.

  METHOD get_includes.
    DATA lt_includes    TYPE ty_source_names.
    DATA lt_new_sources TYPE ty_source_names.
    DATA class_name     TYPE seoclsname.
    DATA lv_percent     TYPE i.
    DATA lv_old_percent TYPE i.

    DATA lv_source_name LIKE LINE OF ct_source_names.
    DATA lv_source_size TYPE i.

    lv_source_size = lines( ct_source_names ).

    LOOP AT ct_source_names INTO lv_source_name.
      IF sy-batch IS INITIAL.
        lv_percent = ( sy-tabix * 100 ) / lv_source_size.
        IF lv_percent <> lv_old_percent.
          show_progress_bar( percent = lv_percent
                             content = |Includes finding { sy-tabix  }/{ lv_source_size }| ).
          lv_old_percent = lv_percent.
        ENDIF.
      ENDIF.

      CLEAR lt_includes.

      CASE lv_source_name+30(2).
        WHEN 'CP'. " class pool
          DELETE ct_source_names INDEX sy-tabix.

          class_name = lv_source_name(30).

          TRANSLATE class_name USING '= '.

          APPEND LINES OF me->get_class_includes( clsname = class_name )
                 TO lt_new_sources.
        WHEN 'IP'. " interface pool
          DELETE ct_source_names INDEX sy-tabix.
          lv_source_name+30(1) = 'U'.
          APPEND lv_source_name TO lt_new_sources.
      ENDCASE.
      CALL FUNCTION 'RS_GET_ALL_INCLUDES'
        EXPORTING
          program    = lv_source_name
        TABLES
          includetab = lt_includes
        EXCEPTIONS
          OTHERS     = 0.
      IF sy-subrc <> 0.
        CONTINUE.
      ENDIF.

      DELETE lt_includes WHERE table_line CP 'LSVIM*'.

      APPEND LINES OF lt_includes TO lt_new_sources.
    ENDLOOP.

    APPEND LINES OF lt_new_sources TO ct_source_names.
  ENDMETHOD.

  METHOD search_sources.
    DATA lv_source_name         LIKE LINE OF sources.
    DATA lt_source              TYPE abaptxt255_tab.
    DATA lt_result              TYPE match_result_tab.
    DATA ls_result              LIKE LINE OF lt_result.

    DATA lv_source_size         TYPE i.
    DATA lv_progbar_text        TYPE string.
    DATA lv_progbar_percent     TYPE i.
    DATA lv_progbar_old_percent TYPE i.

    lv_source_size = lines( sources ).

    LOOP AT sources INTO lv_source_name.
      READ REPORT lv_source_name INTO lt_source.
      IF sy-subrc <> 0.
        CONTINUE.
      ENDIF.

      IF sy-batch IS INITIAL.
        lv_progbar_percent = ( sy-tabix * 100 ) / lv_source_size.
        lv_progbar_text = |Sniffing... for: '{ pattern }' { sy-tabix }/{ lv_source_size } | &&
                          |hits:{ lines( rt_result ) }|.
        IF lv_progbar_percent <> lv_progbar_old_percent.
          show_progress_bar( percent = lv_progbar_percent
                             content = lv_progbar_text ).
          lv_progbar_old_percent = lv_progbar_percent.
        ENDIF.
      ENDIF.

      IF isregex = abap_true.
        FIND ALL OCCURRENCES OF REGEX pattern
             IN TABLE lt_source
             IN CHARACTER MODE
             IGNORING CASE
             RESULTS lt_result.
      ELSE.
        FIND ALL OCCURRENCES OF pattern
             IN TABLE lt_source
             IN CHARACTER MODE
             IGNORING CASE
             RESULTS lt_result.
      ENDIF.

      IF lt_result IS INITIAL.
        CONTINUE.
      ENDIF.

      LOOP AT lt_result INTO ls_result.
        add_to_hit_list( EXPORTING repname   = lv_source_name
                                   repsource = lt_source
                                   matchres  = ls_result
                                   comment   = comment
                         CHANGING  ct_result = rt_result ).
      ENDLOOP.

      CLEAR lt_source.
      CLEAR lt_result.
    ENDLOOP.
  ENDMETHOD.

  METHOD add_to_hit_list.
    DATA source_line LIKE LINE OF repsource.

    READ TABLE repsource INDEX matchres-line INTO source_line.
    IF sy-subrc <> 0.
      RETURN.
    ENDIF.

    " if all line is comment ignore this match
    IF source_line-line(1) CA '"*' AND comment = abap_true.
      RETURN.
    ENDIF.

    APPEND VALUE #( repname = repname
                    linesrc = source_line-line
                    lineidx = matchres-line )
           TO ct_result.
  ENDMETHOD.

  METHOD get_program_names.
    CHECK    repname IS NOT INITIAL
          OR reptype IS NOT INITIAL.

    SELECT name FROM trdir
      WHERE name IN @repname
        AND subc IN @reptype
      INTO TABLE @rt_source_names.
  ENDMETHOD.

  METHOD get_report_names.
    CHECK package IS NOT INITIAL.

    SELECT obj_name FROM tadir
      WHERE pgmid     = 'R3TR'
        AND object    = 'PROG'
        AND devclass IN @package
        AND delflag   = @space
      INTO TABLE @rt_source_names.
  ENDMETHOD.

  METHOD get_function_names.
    DATA lt_function_names TYPE TABLE OF tfdir-funcname.
    DATA lv_function_name  LIKE LINE OF lt_function_names.

    CHECK    package IS NOT INITIAL
          OR funcnam IS NOT INITIAL.

    SELECT tfdir~funcname
      FROM tfdir
             INNER JOIN
               enlfdir ON enlfdir~funcname = tfdir~funcname
                 INNER JOIN
                   tadir ON tadir~obj_name = enlfdir~area
      WHERE tadir~pgmid     = 'R3TR'
        AND tadir~object    = 'FUGR'
        AND tadir~devclass IN @package
        AND tadir~delflag   = @space
        AND tfdir~funcname IN @funcnam
        AND enlfdir~active  = @abap_true
      INTO TABLE @lt_function_names.

    LOOP AT lt_function_names INTO lv_function_name.
      APPEND me->get_function_include( funcname = lv_function_name )
             TO rt_source_names.
    ENDLOOP.
  ENDMETHOD.

  METHOD get_function_group_names.
    DATA lt_obj_names TYPE TABLE OF tadir-obj_name.
    DATA lv_obj_name  LIKE LINE OF lt_obj_names.

    CHECK    package IS NOT INITIAL
          OR funcgrp IS NOT INITIAL.

    SELECT DISTINCT tadir~obj_name FROM tadir
      WHERE tadir~pgmid     = 'R3TR'
        AND tadir~object    = 'FUGR'
        AND tadir~devclass IN @package
        AND tadir~delflag   = @space
        AND tadir~obj_name IN @funcgrp
      INTO TABLE @lt_obj_names.

    LOOP AT lt_obj_names INTO lv_obj_name.
      APPEND me->get_funcgroup_program( funcgroup = CONV #( lv_obj_name ) )
             TO rt_source_names.
    ENDLOOP.
  ENDMETHOD.

  METHOD get_class_names.
    DATA lt_obj_names TYPE TABLE OF tadir-obj_name.
    DATA lv_obj_name  LIKE LINE OF lt_obj_names.

    CHECK    clsname IS NOT INITIAL
          OR package IS NOT INITIAL.

    SELECT obj_name FROM tadir
      WHERE pgmid     = 'R3TR'
        AND object    = 'CLAS'
        AND devclass IN @package
        AND obj_name IN @clsname
        AND delflag   = @space
      INTO TABLE @lt_obj_names.

    LOOP AT lt_obj_names INTO lv_obj_name.
      APPEND cl_oo_classname_service=>get_classpool_name( |{ lv_obj_name }| )
             TO rt_source_names.
    ENDLOOP.
  ENDMETHOD.

  METHOD get_interface_names.
    DATA lt_obj_names TYPE TABLE OF tadir-obj_name.
    DATA lv_obj_name  LIKE LINE OF lt_obj_names.

    CHECK    intface IS NOT INITIAL
          OR package IS NOT INITIAL.

    SELECT obj_name FROM tadir
      WHERE pgmid     = 'R3TR'
        AND object    = 'INTF'
        AND devclass IN @package
        AND obj_name IN @intface
        AND delflag   = @space
      INTO TABLE @lt_obj_names.

    LOOP AT lt_obj_names INTO lv_obj_name.
      APPEND cl_oo_classname_service=>get_interfacepool_name( |{ lv_obj_name }| )
             TO rt_source_names.
    ENDLOOP.
  ENDMETHOD.

  METHOD get_enhancement_names.
    DATA lt_obj_names TYPE TABLE OF tadir-obj_name.
    DATA lv_obj_name  LIKE LINE OF lt_obj_names.

    CHECK    package IS NOT INITIAL
          OR enhance IS NOT INITIAL.

    SELECT obj_name FROM tadir
      WHERE pgmid     = 'R3TR'
        AND object    = 'ENHO'
        AND delflag   = @space
        AND devclass IN @package
        AND obj_name IN @enhance
        AND delflag   = @space
      INTO TABLE @lt_obj_names.

    LOOP AT lt_obj_names INTO lv_obj_name.
      TRANSLATE lv_obj_name(30) USING ' ='.
      lv_obj_name+30 = 'E'.
      APPEND lv_obj_name TO rt_source_names.
    ENDLOOP.
  ENDMETHOD.

  METHOD get_modification_names.
    DATA lt_smodilog TYPE TABLE OF smodilog.
    DATA ls_modi     LIKE LINE OF lt_smodilog.

    CHECK withmod = abap_true.

    DATA lv_obj_name TYPE tadir-obj_name.

    SELECT * FROM smodilog
      WHERE operation NOT IN ( 'MIGR', 'IMPL', 'TRSL', 'NOTE' )
        AND inactive       = @space
        AND int_type  NOT IN ('DUMY')
        AND obj_type      IN ( 'PROG', 'LDBA', 'FUGR', 'FUGX', 'FUGS', 'CLAS' )
        AND sub_type      IN ( 'REPS', 'METH', 'FUNC', 'LDBA', 'CLAS', 'CINC', 'FUG', 'PROG' )
      ORDER BY PRIMARY KEY
      INTO TABLE @lt_smodilog.

    LOOP AT lt_smodilog INTO ls_modi.

      CASE ls_modi-sub_type.
        WHEN 'REPS'. " report
          APPEND ls_modi-sub_name TO rt_source_names.
        WHEN 'METH'. " method
          APPEND me->get_method_include( clsname = CONV #( ls_modi-obj_name )
                                         cpdname = CONV #( ls_modi-sub_name+30 ) )
                 TO rt_source_names.
        WHEN 'FUNC'. " function
          APPEND me->get_function_include( funcname = CONV #( ls_modi-sub_name  ) )
                 TO rt_source_names.
        WHEN 'LDBA'. " logical database
          APPEND |{ ls_modi-sub_name }SEL| TO rt_source_names.
          APPEND |SAP{ ls_modi-sub_name }| TO rt_source_names.
        WHEN 'CLAS'. " class
          APPEND LINES OF me->get_class_includes( clsname = CONV #( ls_modi-obj_name ) )
                 TO rt_source_names.
        WHEN 'CINC'. " class include
          lv_obj_name = ls_modi-sub_name.
          TRANSLATE lv_obj_name USING ' ='.
          lv_obj_name+30 = SWITCH #( ls_modi-sub_type
                                     WHEN 'CPUB' THEN 'CU'
                                     WHEN 'CPRO' THEN 'CO'
                                     WHEN 'CPRI' THEN 'CI' ).
          APPEND lv_obj_name TO rt_source_names.
        WHEN 'FUGR'. " function group
          APPEND me->get_funcgroup_program( funcgroup = CONV #( lv_obj_name ) )
                 TO rt_source_names.
        WHEN 'PROG'. " program
          APPEND lv_obj_name TO rt_source_names.
      ENDCASE.
    ENDLOOP.
  ENDMETHOD.

  METHOD get_class_includes.
    cl_oo_classname_service=>get_all_class_includes( EXPORTING  class_name = clsname
                                                     RECEIVING  result     = rt_includes
                                                     EXCEPTIONS OTHERS     = 1 ).
    DELETE rt_includes WHERE    table_line+30(2) = 'CS'
                             OR table_line+30(2) = 'CP'.
  ENDMETHOD.

  METHOD get_method_include.
    cl_oo_classname_service=>get_method_include( EXPORTING  mtdkey = VALUE #( clsname = clsname
                                                                              cpdname = cpdname )
                                                 RECEIVING  result = rv_include
                                                 EXCEPTIONS OTHERS = 1 ).
  ENDMETHOD.

  METHOD get_function_include.
    CALL FUNCTION 'FUNCTION_EXISTS'
      EXPORTING
        funcname = funcname
      IMPORTING
        include  = rv_include
      EXCEPTIONS
        OTHERS   = 1.
  ENDMETHOD.

  METHOD get_funcgroup_program.
    DATA lv_funcgroup TYPE rs38l-area.

    lv_funcgroup = funcgroup.

    CALL FUNCTION 'FUNCTION_INCLUDE_CONCATENATE'
      CHANGING
        program       = rv_program
        complete_area = lv_funcgroup
      EXCEPTIONS
        OTHERS        = 1.
  ENDMETHOD.
ENDCLASS.


CLASS lcl_application DEFINITION.
  PUBLIC SECTION.
    METHODS initialization.
    METHODS start_of_selection.
    METHODS end_of_selection.

    METHODS handle_on_f4_for_field
      IMPORTING !field   TYPE clike
      CHANGING  cv_value TYPE any.

  PRIVATE SECTION.
    TYPES: BEGIN OF ty_result_header,
             repname TYPE trdir-name,
             expand  TYPE abap_bool,
           END OF ty_result_header.

    METHODS on_link_click
                FOR EVENT link_click OF cl_salv_events_hierseq
      IMPORTING sender
                !level
                !row
                !column.

    METHODS build_alv
      RAISING cx_salv_data_error
              cx_salv_not_found.

    DATA mo_sniffer        TYPE REF TO lcl_sniffer.

    DATA mt_results_body   TYPE lcl_sniffer=>ty_sniff_results.
    DATA ms_results_body   LIKE LINE OF mt_results_body.
    DATA mt_results_header TYPE TABLE OF ty_result_header.
    DATA ms_results_header LIKE LINE OF mt_results_header.
ENDCLASS.


CLASS lcl_application IMPLEMENTATION.
  METHOD initialization.
    mo_sniffer = lcl_sniffer=>get_instance( ).

    sy-title = 'ABAP Sniffer( Code Scanner )'.

    t01 = 'Search Term'.
    %_s_patern_%_app_%-text = 'Search for'.
    %_p_asregx_%_app_%-text = 'Search is regex'.

    t02 = 'Program Selection'.
    %_s_repnam_%_app_%-text = 'Program name'.
    %_s_reptyp_%_app_%-text = 'Program type'.

    t03 = 'Package Selection'.
    %_s_packag_%_app_%-text = 'Package'.

    t04 = 'Function / Function Group Selection'.
    %_s_funcgr_%_app_%-text = 'Function group'.
    %_s_funcnm_%_app_%-text = 'Function name'.

    t05 = 'Class / Interface Selection'.
    %_s_clsnam_%_app_%-text = 'Class'.
    %_s_intfac_%_app_%-text = 'Interface'.

    t06 = 'Enhancement Selection'.
    %_s_enhanc_%_app_%-text = 'Enhancement'.
    %_p_withmd_%_app_%-text = 'With modifications'.

    DATA ls_restrict TYPE sscr_restrict.

    ls_restrict = VALUE #( opt_list_tab = VALUE #( ( name    = 'RESTRICT'
                                                     options = VALUE #( cp = abap_true
                                                                        eq = abap_true ) ) )
                           ass_tab      = VALUE #( ( kind    = 'S'
                                                     name    = 'S_PATERN'
                                                     sg_main = 'I'
                                                     op_main = 'RESTRICT'
                                                     op_addy = 'RESTRICT' ) ) ).

    CALL FUNCTION 'SELECT_OPTIONS_RESTRICT'
      EXPORTING
        program     = sy-repid
        restriction = ls_restrict
      EXCEPTIONS
        OTHERS      = 1.
  ENDMETHOD.

  METHOD start_of_selection.
    DATA lt_pattern TYPE lcl_sniffer=>ty_pattern_tab.

    LOOP AT s_patern INTO s_patern.
      APPEND s_patern-low TO lt_pattern.
    ENDLOOP.

    TRY.
        mt_results_body = mo_sniffer->sniff( pattern = lt_pattern
                                             isregex = p_asregx
                                             repname = s_repnam[]
                                             reptype = s_reptyp[]
                                             package = s_packag[]
                                             funcgrp = s_funcgr[]
                                             funcnam = s_funcnm[]
                                             clsname = s_clsnam[]
                                             intface = s_intfac[]
                                             enhance = s_enhanc[]
                                             withmod = p_withmd ).
      CATCH cx_root INTO DATA(lx_root).
        MESSAGE lx_root->get_text( ) TYPE 'E'.
    ENDTRY.
  ENDMETHOD.

  METHOD end_of_selection.
    IF mt_results_body IS INITIAL.
      MESSAGE |Searched but not found!.| TYPE 'S'.
      RETURN.
    ENDIF.

    LOOP AT mt_results_body INTO DATA(table) GROUP BY ( repname = table-repname ) INTO DATA(group).
      APPEND group-repname TO mt_results_header.
    ENDLOOP.

    TRY.
        build_alv( ).
      CATCH cx_root INTO DATA(lx_root).
        MESSAGE lx_root->get_text( ) TYPE 'E'.
    ENDTRY.
  ENDMETHOD.

  METHOD on_link_click.
    CASE level.
      WHEN 1.
      WHEN 2.
        READ TABLE mt_results_body INDEX row INTO ms_results_body.
        IF sy-subrc <> 0.
          RETURN.
        ENDIF.
        CALL FUNCTION 'EDITOR_PROGRAM'
          EXPORTING
            appid   = 'PG'
            display = abap_true
            program = ms_results_body-repname
            line    = ms_results_body-lineidx
            topline = ms_results_body-lineidx
          EXCEPTIONS
            OTHERS  = 0.
    ENDCASE.
  ENDMETHOD.

  METHOD build_alv.
    DATA lo_salv          TYPE REF TO cl_salv_hierseq_table.
    DATA lo_column        TYPE REF TO cl_salv_column_hierseq.
    DATA lo_disp_settings TYPE REF TO cl_salv_display_settings.

    cl_salv_hierseq_table=>factory(
      EXPORTING t_binding_level1_level2 = VALUE #( ( master = 'REPNAME' slave = 'REPNAME' ) )
      IMPORTING r_hierseq               = lo_salv
      CHANGING  t_table_level1          = mt_results_header
                t_table_level2          = mt_results_body ).

    SET HANDLER on_link_click FOR lo_salv->get_event( ).

    lo_salv->get_layout( )->set_key( VALUE #( report = sy-repid
                                              handle = 'XXXX' ) ).
    lo_salv->get_layout( )->set_save_restriction( ).

    lo_salv->get_functions( )->set_all( ).

    lo_disp_settings = lo_salv->get_display_settings( ).
    lo_disp_settings->set_list_header( value = |{ lines( mt_results_body ) } Hits Found!| ).

    lo_salv->get_columns( level = 1 )->set_expand_column( value = 'EXPAND' ).
    lo_salv->get_level( level = 1 )->set_items_expanded( ).

    LOOP AT lo_salv->get_columns( level = 1 )->get( ) REFERENCE INTO DATA(lr_column).
      CASE lr_column->columnname.
        WHEN 'EXPAND'.
          lr_column->r_column->set_technical( ).
      ENDCASE.
    ENDLOOP.

    LOOP AT lo_salv->get_columns( level = 2 )->get( ) REFERENCE INTO lr_column.
      lo_column ?= lr_column->r_column.
      CASE lr_column->columnname.
        WHEN 'REPNAME'.
          lo_column->set_technical( ).
        WHEN 'LINESRC'.
          lo_column->set_cell_type( if_salv_c_cell_type=>hotspot ).
          lo_column->set_long_text( value = 'Source' ).
        WHEN 'LINEIDX'.
          lo_column->set_long_text( value = 'Line' ).
          lo_column->set_color( value = VALUE #( col = '4' ) ).
          lo_column->set_cell_type( if_salv_c_cell_type=>hotspot ).
          lo_column->set_leading_zero( ).
      ENDCASE.
    ENDLOOP.

    lo_salv->display( ).
  ENDMETHOD.

  METHOD handle_on_f4_for_field.
    CASE field.
      WHEN 'REPNAM'.
        CALL FUNCTION 'REPOSITORY_INFO_SYSTEM_F4'
          EXPORTING
            object_type          = 'PROG'
            object_name          = cv_value
            suppress_selection   = 'X'
          IMPORTING
            object_name_selected = cv_value
          EXCEPTIONS
            cancel               = 0.
    ENDCASE.
  ENDMETHOD.
ENDCLASS.

LOAD-OF-PROGRAM.
  DATA(app) = NEW lcl_application( ).

INITIALIZATION.
  app->initialization( ).

AT SELECTION-SCREEN ON VALUE-REQUEST FOR s_repnam-low.
  app->handle_on_f4_for_field( EXPORTING field    = 'REPNAM'
                               CHANGING  cv_value = s_repnam-low ).

AT SELECTION-SCREEN ON VALUE-REQUEST FOR s_repnam-high.
  app->handle_on_f4_for_field( EXPORTING field    = 'REPNAM'
                               CHANGING  cv_value = s_repnam-high ).

START-OF-SELECTION.
  app->start_of_selection( ).

END-OF-SELECTION.
  app->end_of_selection( ).
