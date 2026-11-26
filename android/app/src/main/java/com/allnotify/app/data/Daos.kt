package com.allnotify.app.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Dao
interface NotificationDao {
    @Query("SELECT * FROM notifications ORDER BY posted_at DESC, id DESC")
    fun observeAll(): Flow<List<NotificationEntity>>

    @Query(
        "SELECT * FROM notifications " +
            "WHERE title LIKE '%' || :query || '%' " +
            "OR body LIKE '%' || :query || '%' " +
            "OR app_name LIKE '%' || :query || '%' " +
            "ORDER BY posted_at DESC, id DESC"
    )
    fun search(query: String): Flow<List<NotificationEntity>>

    @Query("SELECT * FROM notifications WHERE id = :id LIMIT 1")
    suspend fun getById(id: Long): NotificationEntity?

    @Query(
        "SELECT * FROM notifications " +
            "WHERE dedup_hash = :dedupHash " +
            "AND dismissed_at IS NULL " +
            "AND ABS(posted_at - :postedAt) <= :windowMs " +
            "ORDER BY posted_at DESC, id DESC LIMIT 10"
    )
    suspend fun findRecentActiveDuplicates(dedupHash: String, postedAt: Long, windowMs: Long): List<NotificationEntity>

    @Query("SELECT * FROM notifications WHERE dismissed_at IS NULL")
    suspend fun listActive(): List<NotificationEntity>

    @Query("SELECT * FROM notifications WHERE notification_uids_json LIKE '%' || :uidQuoted || '%'")
    suspend fun findByUidPattern(uidQuoted: String): List<NotificationEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entity: NotificationEntity): Long

    @Update
    suspend fun update(entity: NotificationEntity)

    @Query("UPDATE notifications SET dismissed_at = :dismissedAt WHERE id = :id AND dismissed_at IS NULL")
    suspend fun markDismissedById(id: Long, dismissedAt: Long)

    @Query("DELETE FROM notifications")
    suspend fun deleteAll()

    @Query("DELETE FROM notifications WHERE posted_at < :cutoffMs")
    suspend fun deleteOlderThan(cutoffMs: Long): Int

    @Query(
        "DELETE FROM notifications WHERE id NOT IN (" +
            "SELECT id FROM notifications ORDER BY posted_at DESC, id DESC LIMIT :maxRows" +
            ")"
    )
    suspend fun trimToMaxRows(maxRows: Int): Int

    @Query("SELECT attachment_path FROM notifications WHERE attachment_path IS NOT NULL")
    suspend fun listReferencedAttachmentPaths(): List<String>

    @Query("SELECT COUNT(*) FROM notifications")
    suspend fun count(): Int
}

@Dao
interface ActiveKeyMapDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: ActiveKeyMapEntity)

    @Query("SELECT * FROM active_key_map WHERE notification_uid = :uid LIMIT 1")
    suspend fun findByUid(uid: String): ActiveKeyMapEntity?

    @Query("SELECT * FROM active_key_map WHERE sbn_key = :sbnKey")
    suspend fun findBySbnKey(sbnKey: String): List<ActiveKeyMapEntity>

    @Query("DELETE FROM active_key_map WHERE notification_uid = :uid")
    suspend fun deleteByUid(uid: String)

    @Query("DELETE FROM active_key_map WHERE sbn_key = :sbnKey")
    suspend fun deleteBySbnKey(sbnKey: String)

    @Query("DELETE FROM active_key_map WHERE created_at < :cutoffMs")
    suspend fun deleteOlderThan(cutoffMs: Long): Int
}

@Dao
interface AppFilterDao {
    @Query("SELECT * FROM app_filters ORDER BY app_name ASC")
    fun observeAll(): Flow<List<AppFilterEntity>>

    @Query("SELECT * FROM app_filters WHERE package_name = :packageName LIMIT 1")
    suspend fun get(packageName: String): AppFilterEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: AppFilterEntity)
}

@Dao
interface OutboxDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun enqueue(entity: OutboxEntity)

    @Query("SELECT * FROM outbox WHERE created_at >= :minCreatedAt ORDER BY created_at ASC, event_id ASC")
    suspend fun listValid(minCreatedAt: Long): List<OutboxEntity>

    @Query("DELETE FROM outbox WHERE event_id = :eventId")
    suspend fun delete(eventId: String)

    @Query("DELETE FROM outbox WHERE created_at < :cutoffMs")
    suspend fun deleteOlderThan(cutoffMs: Long): Int

    @Query("DELETE FROM outbox")
    suspend fun deleteAll()
}

@Dao
interface KvStateDao {
    @Query("SELECT value FROM kv_state WHERE `key` = :key LIMIT 1")
    suspend fun get(key: String): String?

    @Query("SELECT value FROM kv_state WHERE `key` = :key LIMIT 1")
    fun observe(key: String): Flow<String?>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun put(entity: KvStateEntity)

    @Query("DELETE FROM kv_state WHERE `key` = :key")
    suspend fun delete(key: String)
}
