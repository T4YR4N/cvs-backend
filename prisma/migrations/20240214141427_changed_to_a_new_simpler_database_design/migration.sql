/*
  Warnings:

  - You are about to drop the `Artifact` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `Chunk` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `Match` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `Vuln` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "Chunk" DROP CONSTRAINT "Chunk_detailsHash_vulnId_artifactId_fkey";

-- DropForeignKey
ALTER TABLE "Chunk" DROP CONSTRAINT "Chunk_scanId_fkey";

-- DropForeignKey
ALTER TABLE "Match" DROP CONSTRAINT "Match_artifactId_fkey";

-- DropForeignKey
ALTER TABLE "Match" DROP CONSTRAINT "Match_vulnId_fkey";

-- DropForeignKey
ALTER TABLE "Vuln" DROP CONSTRAINT "Vuln_newVersionId_fkey";

-- AlterTable
ALTER TABLE "Scan" ADD COLUMN     "result" JSONB;

-- DropTable
DROP TABLE "Artifact";

-- DropTable
DROP TABLE "Chunk";

-- DropTable
DROP TABLE "Match";

-- DropTable
DROP TABLE "Vuln";

-- DropEnum
DROP TYPE "ChunkType";
