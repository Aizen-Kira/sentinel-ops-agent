CREATE TABLE `investigation_jobs` (
	`id` varchar(64) NOT NULL,
	`investigation_id` varchar(64) NOT NULL,
	`status` enum('pending','running','done','failed') NOT NULL DEFAULT 'pending',
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`artifact` json,
	CONSTRAINT `investigation_jobs_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `investigation_reports` (
	`id` varchar(64) NOT NULL,
	`investigation_id` varchar(64) NOT NULL,
	`status` enum('pending','running','completed','failed') NOT NULL DEFAULT 'pending',
	`format` enum('markdown','pdf') NOT NULL DEFAULT 'markdown',
	`content` text,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `investigation_reports_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `realtime_events` (
	`id` varchar(64) NOT NULL,
	`tenant_id` varchar(64) NOT NULL DEFAULT 'default',
	`topic` varchar(128) NOT NULL,
	`payload` json,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`replayed` boolean NOT NULL DEFAULT false,
	CONSTRAINT `realtime_events_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `response_actions` (
	`id` varchar(64) NOT NULL,
	`investigation_id` varchar(64) NOT NULL,
	`action_type` enum('ticket','disable_user','isolate_host','block_ioc') NOT NULL,
	`proposed_by` int NOT NULL,
	`approved_by` int,
	`status` enum('proposed','approved','executed','failed') NOT NULL DEFAULT 'proposed',
	`executed_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `response_actions_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `investigation_jobs_investigation_idx` ON `investigation_jobs` (`investigation_id`);--> statement-breakpoint
CREATE INDEX `investigation_jobs_status_idx` ON `investigation_jobs` (`status`);--> statement-breakpoint
CREATE INDEX `investigation_jobs_created_at_idx` ON `investigation_jobs` (`created_at`);--> statement-breakpoint
CREATE INDEX `investigation_reports_investigation_idx` ON `investigation_reports` (`investigation_id`);--> statement-breakpoint
CREATE INDEX `investigation_reports_status_idx` ON `investigation_reports` (`status`);--> statement-breakpoint
CREATE INDEX `realtime_events_topic_idx` ON `realtime_events` (`topic`);--> statement-breakpoint
CREATE INDEX `realtime_events_tenant_idx` ON `realtime_events` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `realtime_events_created_at_idx` ON `realtime_events` (`created_at`);--> statement-breakpoint
CREATE INDEX `response_actions_investigation_idx` ON `response_actions` (`investigation_id`);--> statement-breakpoint
CREATE INDEX `response_actions_status_idx` ON `response_actions` (`status`);--> statement-breakpoint
CREATE INDEX `response_actions_proposed_by_idx` ON `response_actions` (`proposed_by`);