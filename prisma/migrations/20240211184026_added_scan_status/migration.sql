/*
  Warnings:

  - Added the required column `status` to the `Scan` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "ScanStatus" AS ENUM ('PENDING', 'COMPLETED', 'FAILED');

-- AlterTable
ALTER TABLE "Scan" ADD COLUMN     "status" "ScanStatus" NOT NULL;
