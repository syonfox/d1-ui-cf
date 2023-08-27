/**
 * This route dumps a database into a file.
 */
import { redirect } from "@sveltejs/kit";

export const GET: RequestHandler = async ({ params }) => {
	return redirect(301, `/api/db/${params.database}/dump/db-${params.database}.sqlite3`);
};
