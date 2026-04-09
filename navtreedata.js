/*
 @licstart  The following is the entire license notice for the JavaScript code in this file.

 The MIT License (MIT)

 Copyright (C) 1997-2020 by Dimitri van Heesch

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute,
 sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or
 substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 @licend  The above is the entire license notice for the JavaScript code in this file
*/
var NAVTREE =
[
  [ "SH2SC-EDT", "index.html", [
    [ "Abstract", "index.html#autotoc_md2", null ],
    [ "Core Features", "index.html#autotoc_md4", null ],
    [ "Protocol Specification: C2P-ARQ", "index.html#autotoc_md6", [
      [ "Wire Format", "index.html#autotoc_md7", [
        [ "HelloPacket — 15 bytes on wire", "index.html#autotoc_md8", null ],
        [ "DataPacket (FLAG_DAT / FLAG_FIN) — 17 bytes on wire", "index.html#autotoc_md9", null ]
      ] ],
      [ "ARQ Parameters", "index.html#autotoc_md10", null ],
      [ "FIFO Drain (Stale Buffer Prevention)", "index.html#autotoc_md11", null ]
    ] ],
    [ "Security Model", "index.html#autotoc_md13", [
      [ "Authenticated Encryption Pipeline", "index.html#autotoc_md14", null ],
      [ "Replay Attack Resistance", "index.html#autotoc_md15", null ],
      [ "Secure Key Material Destruction", "index.html#autotoc_md16", null ]
    ] ],
    [ "FSM State Reference", "index.html#autotoc_md18", [
      [ "Transmitter — <tt>TxState</tt> (9 states)", "index.html#autotoc_md19", null ],
      [ "Receiver — byte-level <tt>ParseState</tt>", "index.html#autotoc_md20", null ],
      [ "Receiver display / watchdog — <tt>RxState</tt>", "index.html#autotoc_md21", null ]
    ] ],
    [ "Hardware and Environment", "index.html#autotoc_md23", [
      [ "Target Hardware", "index.html#autotoc_md24", null ],
      [ "Required Libraries", "index.html#autotoc_md25", null ],
      [ "Build Environment", "index.html#autotoc_md26", null ]
    ] ],
    [ "Repository Structure", "index.html#autotoc_md28", null ],
    [ "Key Constants Reference", "index.html#autotoc_md30", null ],
    [ "Academic Context", "index.html#autotoc_md32", null ],
    [ "SH2SC-EDT", "md_README__uk.html", [
      [ "Анотація", "md_README__uk.html#autotoc_md35", null ],
      [ "Основні можливості", "md_README__uk.html#autotoc_md37", null ],
      [ "Специфікація протоколу: C2P-ARQ", "md_README__uk.html#autotoc_md39", [
        [ "Формат кадру", "md_README__uk.html#autotoc_md40", [
          [ "HelloPacket — 15 байт на дроті", "md_README__uk.html#autotoc_md41", null ],
          [ "DataPacket (FLAG_DAT / FLAG_FIN) — 17 байт на дроті", "md_README__uk.html#autotoc_md42", null ]
        ] ],
        [ "Параметри ARQ", "md_README__uk.html#autotoc_md43", null ],
        [ "Очищення FIFO (запобігання «отруєнню» буфером)", "md_README__uk.html#autotoc_md44", null ]
      ] ],
      [ "Модель безпеки", "md_README__uk.html#autotoc_md46", [
        [ "Конвеєр автентифікованого шифрування", "md_README__uk.html#autotoc_md47", null ],
        [ "Стійкість до атак повторного відтворення", "md_README__uk.html#autotoc_md48", null ],
        [ "Безпечне знищення ключового матеріалу", "md_README__uk.html#autotoc_md49", null ]
      ] ],
      [ "Довідник станів кінцевих автоматів", "md_README__uk.html#autotoc_md51", [
        [ "Передавач — <tt>TxState</tt> (9 станів)", "md_README__uk.html#autotoc_md52", null ],
        [ "Приймач — байтовий <tt>ParseState</tt>", "md_README__uk.html#autotoc_md53", null ],
        [ "Відображення/сторожовий таймер приймача — <tt>RxState</tt>", "md_README__uk.html#autotoc_md54", null ]
      ] ],
      [ "Апаратне забезпечення та середовище", "md_README__uk.html#autotoc_md56", [
        [ "Цільове обладнання", "md_README__uk.html#autotoc_md57", null ],
        [ "Необхідні бібліотеки", "md_README__uk.html#autotoc_md58", null ],
        [ "Середовище збирання", "md_README__uk.html#autotoc_md59", null ]
      ] ],
      [ "Структура репозиторію", "md_README__uk.html#autotoc_md61", null ],
      [ "Довідник ключових констант", "md_README__uk.html#autotoc_md63", null ],
      [ "Академічний контекст", "md_README__uk.html#autotoc_md65", null ]
    ] ],
    [ "Topics", "topics.html", "topics" ],
    [ "Data Structures", "annotated.html", [
      [ "Data Structures", "annotated.html", "annotated_dup" ],
      [ "Data Structure Index", "classes.html", null ],
      [ "Data Fields", "functions.html", [
        [ "All", "functions.html", null ],
        [ "Variables", "functions_vars.html", null ]
      ] ]
    ] ],
    [ "Files", "files.html", [
      [ "File List", "files.html", "files_dup" ],
      [ "Globals", "globals.html", [
        [ "All", "globals.html", null ],
        [ "Functions", "globals_func.html", null ],
        [ "Variables", "globals_vars.html", null ],
        [ "Enumerations", "globals_enum.html", null ],
        [ "Enumerator", "globals_eval.html", null ]
      ] ]
    ] ]
  ] ]
];

var NAVTREEINDEX =
[
"ReceiverNode_2csprng_8h.html",
"topics.html"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';