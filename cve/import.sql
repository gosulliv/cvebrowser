create table CVE(
 name string,
 status string,
 description string,
 refs string,
 phase string,
 votes string,
 comments string);


.mode csv
.separator ','
.import actual-utf8.csv CVE

