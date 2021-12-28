/**
 * @name Empty block
 * @kind problem
 * @problem.severity warning
 * @id java/example/empty-block
 */

import java

from Method method
where method.hasName("request")
select method, method.getDeclaringType()