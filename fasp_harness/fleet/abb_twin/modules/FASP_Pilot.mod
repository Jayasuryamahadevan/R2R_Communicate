MODULE FASP_Pilot
    ! FASP pilot mailbox v1 for ABB GoFa / OmniCore.
    !
    ! This module contains no motion target and no safety function. An ABB-
    ! authorised programmer may add a separately risk-assessed routine and a
    ! matching explicit command branch. Never turn fasp_command into a dynamic
    ! procedure name, joint target, robtarget, speed, zone, or I/O address.

    PERS string fasp_protocol_version := "1";
    PERS num fasp_command_seq := 0;
    PERS num fasp_ack_seq := 0;
    PERS string fasp_mission_id := "none";
    PERS string fasp_command := "none";
    PERS string fasp_result := "IDLE";
    PERS string fasp_detail := "local_start";
    PERS bool fasp_cancel_requested := FALSE;

    PROC FASP_PilotMain()
        VAR num accepted_seq;

        ! A controller/task restart must never replay an interrupted physical
        ! action. Drop an unacknowledged command and make the failure visible.
        IF fasp_command_seq <> fasp_ack_seq THEN
            fasp_result := "FAILED";
            fasp_detail := "restart_refused_replay";
            fasp_ack_seq := fasp_command_seq;
        ELSE
            fasp_result := "IDLE";
            fasp_detail := "ready";
        ENDIF
        fasp_cancel_requested := FALSE;

        WHILE TRUE DO
            IF fasp_command_seq > fasp_ack_seq THEN
                accepted_seq := fasp_command_seq;
                fasp_result := "RUNNING";
                fasp_detail := "started";

                IF fasp_command = "pilot_noop" THEN
                    ! First commissioning command: proves the authenticated
                    ! path and lifecycle without moving the arm.
                    WaitTime 0.10;
                    IF fasp_cancel_requested THEN
                        fasp_result := "CANCELLED";
                        fasp_detail := "cancelled";
                    ELSE
                        fasp_result := "COMPLETED";
                        fasp_detail := "noop_complete";
                    ENDIF
                ELSE
                    fasp_result := "REJECTED";
                    fasp_detail := "command_not_taught";
                ENDIF

                ! Acknowledge only after the selected branch reaches a terminal
                ! state. The Python side will not commit another command first.
                fasp_ack_seq := accepted_seq;
                fasp_cancel_requested := FALSE;
            ENDIF
            WaitTime 0.05;
        ENDWHILE
    ENDPROC
ENDMODULE
