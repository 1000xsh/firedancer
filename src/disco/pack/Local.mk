$(call add-hdrs,fd_pack.h fd_est_tbl.h fd_compute_budget_program.h)
$(call add-objs,fd_pack,fd_disco)
$(call make-unit-test,test_compute_budget_program,test_compute_budget_program,fd_disco fd_tango fd_ballet fd_util)
$(call make-unit-test,test_est_tbl,test_est_tbl,fd_disco fd_tango fd_ballet fd_util)
$(call make-unit-test,test_pack,test_pack,fd_disco fd_tango fd_ballet fd_util)
$(call make-bin,fd_pack_ctl,fd_pack_ctl,fd_util fd_disco fd_tango fd_ballet)
