# usermode_edr_demonstrator
Its a poc demonstrator for the user mode edr dll. It creates a process in suspended mode. Queues a APC (using QueueUserAPC() api) to load the edr .dll and resumes the process.
