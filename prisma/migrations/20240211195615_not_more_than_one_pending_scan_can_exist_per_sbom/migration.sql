/*
  Warnings:

  - A unique constraint covering the columns `[sbomId,status]` on the table `Scan` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateIndex
CREATE UNIQUE INDEX "Scan_sbomId_status_key" ON "Scan"("sbomId", "status");
