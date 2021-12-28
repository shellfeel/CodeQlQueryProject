import java 
import semmle.code.java.dataflow.DataFlow

from *
where print.hasName("println") and 
select print, x