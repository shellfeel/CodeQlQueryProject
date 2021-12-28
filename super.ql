/**
 * 
 */
import java

from Callable callee
where callee.getCompilationUnit().fromSource() and not callee.isPublic()
select callee